-- Users and authentication -------------------------------------------------

CREATE TABLE users (
  id                 TEXT PRIMARY KEY,
  email              TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email_verified_at  INTEGER,
  -- "pbkdf2-sha256$<iterations>$<salt b64>$<hash b64>", NULL for Google-only accounts
  password_hash      TEXT,
  google_sub         TEXT UNIQUE,
  -- TOTP secret, encrypted with the master key (see lib/keywrap.ts)
  totp_secret_enc    TEXT,
  totp_enabled_at    INTEGER,
  -- Last accepted TOTP time step, to block replay of the same code
  totp_last_step     INTEGER,
  created_at         INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  used_at    INTEGER,
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE sessions (
  -- SHA-256 of the session token; the token itself is only in the cookie
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- NULL until the second factor is verified (or the user has none yet)
  mfa_at        INTEGER,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  ip            TEXT,
  user_agent    TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

-- Single-use tokens for email verification and password reset
CREATE TABLE tokens (
  id          TEXT PRIMARY KEY,      -- SHA-256 of the token
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL CHECK (kind IN ('verify_email', 'reset_password')),
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);
CREATE INDEX tokens_user ON tokens(user_id, kind);

-- Certificate authorities --------------------------------------------------

CREATE TABLE cas (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind              TEXT NOT NULL CHECK (kind IN ('root', 'intermediate')),
  parent_id         TEXT REFERENCES cas(id) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  subject           TEXT NOT NULL,
  serial            TEXT NOT NULL,
  key_algorithm     TEXT NOT NULL,
  not_before        INTEGER NOT NULL,
  not_after         INTEGER NOT NULL,
  fingerprint       TEXT NOT NULL,     -- SHA-256 of the DER certificate, hex
  cert_pem          TEXT NOT NULL,
  -- Root only: the permitted subtrees, JSON {"dns": [...], "ip": [...]}
  name_constraints  TEXT,
  -- Intermediate only: the private key, encrypted with the master key
  key_enc           TEXT,
  -- Latest CRL issued by this CA (DER, base64). Roots: signed in the browser.
  crl_der           TEXT,
  crl_number        INTEGER NOT NULL DEFAULT 0,
  crl_next_update   INTEGER,
  revoked_at        INTEGER,
  revocation_reason INTEGER,
  created_at        INTEGER NOT NULL,
  UNIQUE (user_id, fingerprint)
);
CREATE INDEX cas_user ON cas(user_id);
CREATE INDEX cas_parent ON cas(parent_id);

-- Issued end-entity certificates (the inventory) ---------------------------

CREATE TABLE certificates (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ca_id             TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
  serial            TEXT NOT NULL,
  common_name       TEXT NOT NULL,
  sans              TEXT NOT NULL,     -- JSON {"dns": [...], "ip": [...]}
  profile           TEXT NOT NULL CHECK (profile IN ('server', 'client')),
  key_algorithm     TEXT NOT NULL,
  not_before        INTEGER NOT NULL,
  not_after         INTEGER NOT NULL,
  fingerprint       TEXT NOT NULL,
  cert_pem          TEXT NOT NULL,
  tags              TEXT NOT NULL DEFAULT '[]',
  notes             TEXT NOT NULL DEFAULT '',
  revoked_at        INTEGER,
  revocation_reason INTEGER,
  created_at        INTEGER NOT NULL,
  UNIQUE (ca_id, serial)
);
CREATE INDEX certificates_user ON certificates(user_id, created_at DESC);
CREATE INDEX certificates_ca ON certificates(ca_id);
CREATE INDEX certificates_fingerprint ON certificates(user_id, fingerprint);

-- Audit log ----------------------------------------------------------------

CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
  action      TEXT NOT NULL,
  target      TEXT,
  meta        TEXT,
  ip          TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX audit_user ON audit_log(user_id, created_at DESC);
