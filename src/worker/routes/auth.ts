import { Hono } from "hono";
import type { AppContext, AppEnv, UserRow } from "../lib/context";
import { hashPassword, passwordProblem, verifyPassword } from "../lib/password";
import { seal, unseal } from "../lib/secrets";
import { appOrigin, audit, rateLimit, sendEmail } from "../lib/services";
import {
  createSession,
  currentUser,
  destroyOtherSessions,
  destroySession,
  isFullyAuthenticated,
  markSessionMfa,
  requireAuth,
} from "../lib/session";
import {
  generateRecoveryCodes,
  generateTotpSecret,
  normalizeRecoveryCode,
  totpUri,
  verifyTotp,
} from "../lib/totp";
import { EMAIL_RE, fail, now, randomId, randomToken, sha256Hex } from "../lib/util";
import { readJson } from "./json";

export const auth = new Hono<AppEnv>();

const VERIFY_TTL_MS = 48 * 3600_000;
const RESET_TTL_MS = 3600_000;


function normalizeEmail(email: unknown): string {
  if (typeof email !== "string" || !EMAIL_RE.test(email.trim())) fail(400, "invalid_email", "Enter a valid email address");
  return email.trim().toLowerCase();
}

/** What the frontend needs to know about the current user. */
export function userView(c: AppContext) {
  const s = c.get("session");
  if (!s) return { user: null };
  return {
    user: {
      id: s.user.id,
      email: s.user.email,
      emailVerified: !!s.user.email_verified_at,
      hasPassword: !!s.user.password_hash,
      google: !!s.user.google_sub,
      mfaEnabled: !!s.user.totp_enabled_at,
    },
    // "full": ready for CA work; "mfa": must enter a code; "setup": must enable 2FA first
    stage: !isFullyAuthenticated(s) ? "mfa" : s.user.totp_enabled_at ? "full" : "setup",
  };
}

async function issueToken(c: AppContext, userId: string, kind: "verify_email" | "reset_password", ttl: number) {
  const token = randomToken();
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM tokens WHERE user_id = ? AND kind = ? AND used_at IS NULL").bind(userId, kind),
    c.env.DB.prepare("INSERT INTO tokens (id, user_id, kind, expires_at) VALUES (?, ?, ?, ?)").bind(
      await sha256Hex(token),
      userId,
      kind,
      now() + ttl,
    ),
  ]);
  return token;
}

/** Marks a token used and returns its user id, or fails. Single use. */
async function consumeToken(c: AppContext, token: unknown, kind: "verify_email" | "reset_password"): Promise<string> {
  if (typeof token !== "string" || !token) fail(400, "invalid_token", "This link is invalid or has expired");
  const row = await c.env.DB.prepare(
    "UPDATE tokens SET used_at = ? WHERE id = ? AND kind = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id",
  )
    .bind(now(), await sha256Hex(token), kind, now())
    .first<{ user_id: string }>();
  if (!row) fail(400, "invalid_token", "This link is invalid or has expired");
  return row.user_id;
}

async function sendVerification(c: AppContext, user: Pick<UserRow, "id" | "email">) {
  const token = await issueToken(c, user.id, "verify_email", VERIFY_TTL_MS);
  await sendEmail(c.env, {
    to: user.email,
    subject: "Confirm your email",
    text: `Confirm your email address for n25tech PKI:\n\n${appOrigin(c)}/verify-email#token=${token}\n\nThis link expires in 48 hours. If you didn't create an account, ignore this email.`,
  });
}

// ---------------------------------------------------------------------------

auth.get("/me", (c) => c.json(userView(c)));

auth.post("/register", async (c) => {
  const b = await readJson<{ email: string; password: string }>(c);
  const email = normalizeEmail(b.email);
  await rateLimit(c, "register", email);
  const problem = passwordProblem(b.password);
  if (problem) fail(400, "weak_password", problem);

  const id = randomId();
  const hash = await hashPassword(c.env, b.password!);
  const inserted = await c.env.DB.prepare(
    "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO NOTHING RETURNING id",
  )
    .bind(id, email, hash, now())
    .first();
  if (!inserted) fail(409, "email_taken", "An account with this email already exists. Try signing in.");

  await audit(c, id, "account.register");
  await sendVerification(c, { id, email });
  await createSession(c, id, false);
  return c.json({ ok: true }, 201);
});

auth.post("/login", async (c) => {
  const b = await readJson<{ email: string; password: string }>(c);
  const email = normalizeEmail(b.email);
  await rateLimit(c, "login", email);
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first<UserRow>();
  const ok = await verifyPassword(c.env, String(b.password ?? ""), user?.password_hash ?? null);
  if (!user || !ok) {
    if (user) await audit(c, user.id, "login.failed");
    fail(401, "invalid_credentials", "Incorrect email or password");
  }
  await destroySession(c);
  await createSession(c, user.id, false);
  await audit(c, user.id, "login.password");
  return c.json({ mfaRequired: !!user.totp_enabled_at });
});

auth.post("/logout", async (c) => {
  const s = c.get("session");
  await destroySession(c);
  if (s) await audit(c, s.user.id, "logout");
  return c.json({ ok: true });
});

// --- Second factor ---------------------------------------------------------

auth.post("/mfa", async (c) => {
  const s = c.get("session");
  if (!s) fail(401, "unauthenticated", "Please sign in");
  if (!s.user.totp_enabled_at || !s.user.totp_secret_enc) fail(400, "mfa_not_enabled");
  await rateLimit(c, "mfa", s.user.id);
  const b = await readJson<{ code: string; recoveryCode: string }>(c);

  if (b.recoveryCode) {
    const hash = await sha256Hex(normalizeRecoveryCode(String(b.recoveryCode)));
    const used = await c.env.DB.prepare(
      "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL RETURNING code_hash",
    )
      .bind(now(), s.user.id, hash)
      .first();
    if (!used) {
      await audit(c, s.user.id, "mfa.failed", null, { method: "recovery" });
      fail(401, "invalid_code", "That recovery code isn't valid");
    }
    await markSessionMfa(c);
    await audit(c, s.user.id, "mfa.recovery_code_used");
    return c.json({ ok: true });
  }

  const secret = new TextDecoder().decode(await unseal(c.env, s.user.totp_secret_enc, `totp:${s.user.id}`));
  const step = await verifyTotp(secret, String(b.code ?? ""));
  // Accept each code once: the step must be newer than the last one used.
  const accepted =
    step !== null &&
    (await c.env.DB.prepare(
      "UPDATE users SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?) RETURNING id",
    )
      .bind(step, s.user.id, step)
      .first());
  if (!accepted) {
    await audit(c, s.user.id, "mfa.failed", null, { method: "totp" });
    fail(401, "invalid_code", "That code isn't valid. Check your authenticator app and try again.");
  }
  await markSessionMfa(c);
  await audit(c, s.user.id, "mfa.totp");
  return c.json({ ok: true });
});

/** Starts TOTP enrolment: stores a pending secret and returns it for the authenticator app. */
auth.post("/totp/setup", requireAuth, async (c) => {
  const user = currentUser(c);
  if (user.totp_enabled_at) fail(409, "mfa_already_enabled", "Two-factor authentication is already on");
  const secret = generateTotpSecret();
  await c.env.DB.prepare("UPDATE users SET totp_secret_enc = ? WHERE id = ?")
    .bind(await seal(c.env, new TextEncoder().encode(secret), `totp:${user.id}`), user.id)
    .run();
  return c.json({ secret, uri: totpUri(secret, user.email) });
});

/** Confirms enrolment with a first code; returns one-time recovery codes. */
auth.post("/totp/enable", requireAuth, async (c) => {
  const user = currentUser(c);
  if (user.totp_enabled_at) fail(409, "mfa_already_enabled", "Two-factor authentication is already on");
  if (!user.totp_secret_enc) fail(400, "mfa_setup_not_started", "Start setup first");
  await rateLimit(c, "mfa", user.id);
  const b = await readJson<{ code: string }>(c);
  const secret = new TextDecoder().decode(await unseal(c.env, user.totp_secret_enc, `totp:${user.id}`));
  const step = await verifyTotp(secret, String(b.code ?? ""));
  if (step === null) fail(400, "invalid_code", "That code isn't valid. Check your authenticator app and try again.");

  const codes = generateRecoveryCodes();
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE users SET totp_enabled_at = ?, totp_last_step = ? WHERE id = ?").bind(now(), step, user.id),
    c.env.DB.prepare("DELETE FROM recovery_codes WHERE user_id = ?").bind(user.id),
    ...(await Promise.all(
      codes.map(async (code) =>
        c.env.DB.prepare("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)").bind(user.id, await sha256Hex(code)),
      ),
    )),
  ]);
  user.totp_enabled_at = now();
  await markSessionMfa(c);
  await destroyOtherSessions(c, user.id, true);
  await audit(c, user.id, "mfa.enabled");
  return c.json({ recoveryCodes: codes });
});

// --- Email verification ----------------------------------------------------

auth.post("/verify-email", async (c) => {
  const b = await readJson<{ token: string }>(c);
  const userId = await consumeToken(c, b.token, "verify_email");
  await c.env.DB.prepare("UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?) WHERE id = ?").bind(now(), userId).run();
  await audit(c, userId, "account.email_verified");
  return c.json({ ok: true });
});

auth.post("/resend-verification", requireAuth, async (c) => {
  const user = currentUser(c);
  await rateLimit(c, "verify", user.id);
  if (!user.email_verified_at) await sendVerification(c, user);
  return c.json({ ok: true });
});

// --- Password reset --------------------------------------------------------

auth.post("/forgot", async (c) => {
  const b = await readJson<{ email: string }>(c);
  const email = normalizeEmail(b.email);
  await rateLimit(c, "forgot", email);
  const user = await c.env.DB.prepare("SELECT id, email FROM users WHERE email = ?").bind(email).first<UserRow>();
  if (user) {
    const token = await issueToken(c, user.id, "reset_password", RESET_TTL_MS);
    await sendEmail(c.env, {
      to: user.email,
      subject: "Reset your password",
      text: `Someone asked to reset the password for your n25tech PKI account.\n\n${appOrigin(c)}/reset-password#token=${token}\n\nThis link expires in 1 hour. If it wasn't you, ignore this email; your password hasn't changed.`,
    });
    await audit(c, user.id, "password.reset_requested");
  }
  // Same answer either way, so this can't be used to discover accounts.
  return c.json({ ok: true });
});

auth.post("/reset", async (c) => {
  const b = await readJson<{ token: string; password: string }>(c);
  await rateLimit(c, "reset");
  const problem = passwordProblem(b.password);
  if (problem) fail(400, "weak_password", problem);
  const userId = await consumeToken(c, b.token, "reset_password");
  // A reset link proves control of the inbox, so the email counts as verified.
  await c.env.DB.prepare("UPDATE users SET password_hash = ?, email_verified_at = COALESCE(email_verified_at, ?) WHERE id = ?")
    .bind(await hashPassword(c.env, b.password!), now(), userId)
    .run();
  await destroyOtherSessions(c, userId, false);
  await audit(c, userId, "password.reset");
  // The second factor is still required at the next sign-in.
  return c.json({ ok: true });
});

auth.post("/password", requireAuth, async (c) => {
  const user = currentUser(c);
  const b = await readJson<{ currentPassword: string; newPassword: string }>(c);
  await rateLimit(c, "password", user.id);
  if (user.password_hash && !(await verifyPassword(c.env, String(b.currentPassword ?? ""), user.password_hash))) {
    fail(401, "invalid_credentials", "Your current password is incorrect");
  }
  const problem = passwordProblem(b.newPassword);
  if (problem) fail(400, "weak_password", problem);
  await c.env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(await hashPassword(c.env, b.newPassword!), user.id).run();
  await destroyOtherSessions(c, user.id, true);
  await audit(c, user.id, "password.changed");
  return c.json({ ok: true });
});
