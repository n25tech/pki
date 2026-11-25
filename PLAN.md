# pki.n25tech.com — Project Plan

A hosted private certificate authority for homelabs and teams running internal services without a public domain. Users create their own CA hierarchy, issue certificates, keep an inventory of what they issued, revoke individual certificates, and look up whether a certificate came from one of their CAs.

> **Disclaimer (shown in the app and README):** This is a convenience tool for labs and internal, non-critical use. It is not a hardened or production PKI. For anything with a real security requirement, use Let's Encrypt or a properly operated CA.

## Stack

- **Frontend:** Cloudflare Pages (`web/`)
- **API:** Cloudflare Worker (`api/`), routed at `pki.n25tech.com/api/*`
- **Data:** D1 (users, CAs, certificates, revocations, audit log), KV (cached CRLs)
- **Secrets:** Worker secrets (master wrapping key, OAuth secret, email API key, session secret)
- **Crypto:** WebCrypto + `@peculiar/x509` / `pkijs`, ECDSA P-256/P-384 by default (RSA available, slower)

## Hostnames

| Purpose | Host | Notes |
|---|---|---|
| App + API | `pki.n25tech.com` | API at `/api/*` (same origin, no CORS) |
| CRL / AIA | `pki-crl.n25tech.com` | Embedded in every certificate, so it must **never change**. Also served over plain HTTP (exempt from "Always Use HTTPS"). |
| ACME (Phase 3) | `pki-acme.n25tech.com` | Stable; goes into client configs |

Flat hostnames are covered by Cloudflare's free Universal SSL. Session cookies are host-only on `pki.n25tech.com` (no `Domain=.n25tech.com`).

## Security principles

1. **Root keys never reach the server.** Roots are generated in the browser and the user downloads the root key.
2. **Name constraints are mandatory** on every root (e.g. `.home.arpa`, `.lan`, `.internal`, a user-chosen suffix, RFC1918/ULA IP ranges), so a leaked key can't sign public domains. The server enforces this on every issuance, not just the UI.
3. **Intermediate keys are stored encrypted**: a per-user data key, wrapped by a master key held in Worker secrets (optionally also by a passphrase-derived key).
4. **Leaf keys can be generated in the browser**, so the server only ever sees a CSR.
5. **2FA is mandatory** before any CA can be created. An account effectively *is* a CA.
6. **No secrets in git.** The repo is public, and all credentials live in Worker or GitHub Actions secrets.

---

## Phase 1 — MVP

### Foundations
- [ ] Monorepo: `web/` (Pages), `api/` (Worker), shared TypeScript types
- [ ] `wrangler.toml` with D1 + KV bindings; staging and production environments
- [ ] `.gitignore` (`.dev.vars`, `.env*`, `*.pem`, `*.key`, `node_modules`, build output)
- [ ] `SECURITY.md` with private vulnerability reporting; license; README with disclaimer
- [ ] CI: lint, typecheck and tests on PRs; deploy only on push to `master`; Actions pinned to SHAs; least-privilege Cloudflare token; no `pull_request_target`
- [ ] **Spike:** generate a root, intermediate, leaf and CRL with `@peculiar/x509` inside the Workers runtime; measure CPU time for ECDSA vs RSA

### Auth
- [ ] Email/password (scrypt or Argon2), email verification, password reset
- [ ] Google OAuth (redirect URI on `pki.n25tech.com`)
- [ ] TOTP + passkeys; 2FA required before CA creation
- [ ] Sessions (HttpOnly, Secure, SameSite, host-only), CSRF protection, rate limiting
- [ ] Audit log of security-relevant events

### CA core
- [ ] Browser-side root generation with a required name-constraints editor; root key downloaded by the user, never uploaded
- [ ] Root signs intermediate(s) in the browser; the intermediate key is encrypted and stored server-side
- [ ] Multiple intermediates per root (per site or environment)
- [ ] CA detail pages: subject, validity, constraints, fingerprints, chain download

### Certificates & inventory
- [ ] Issue from a browser-generated key, or from a pasted CSR
- [ ] Profiles: TLS server, TLS client; SAN editor (DNS + IP)
- [ ] Server-side policy: reject anything outside the root's name constraints
- [ ] Exports: PEM, full chain, PKCS#12/PFX, Kubernetes secret YAML
- [ ] Inventory: search, filter by CA, expiry status, tags, notes

### Revocation & lookup
- [ ] Revoke with a reason code; inventory updates immediately
- [ ] Per-CA CRL at `pki-crl.n25tech.com/<ca-id>.crl`, regenerated on revocation and on a cron schedule, cached in KV
- [ ] Lookup by uploading a certificate or pasting a serial or fingerprint: verify the chain and report the issuing CA and status (valid / revoked / expired / unknown)

### Pre-launch
- [ ] Trust-store install guides: Windows, macOS, Linux (Debian/Ubuntu, Fedora/RHEL, Arch), iOS, Android, Firefox, Java keystore, Docker
- [ ] Disclaimer, terms, privacy pages
- [ ] Account export (CAs + inventory) and account deletion that destroys stored keys
- [ ] CSP, security headers, dependency audit

## Phase 2 — Day-to-day usability
- [ ] Expiry warning emails (Cron Triggers; SPF/DKIM/DMARC configured)
- [ ] API tokens + scripting examples (curl / small CLI)
- [ ] Bulk issuance; "duplicate this certificate"

## Phase 3 — ACME
- [ ] RFC 8555 endpoint per intermediate at `pki-acme.n25tech.com/<ca-id>/directory`
- [ ] Authorization via External Account Binding plus name constraints (no HTTP-01 for private hosts)
- [ ] Short default lifetimes (7–30 days) to make up for weak CRL checking by clients
- [ ] Tested with Caddy, Traefik, certbot, cert-manager, acme.sh

## Phase 4 — Extras
- [ ] Teams/organisations with roles
- [ ] SSH certificates
- [ ] External security review
- [ ] OCSP (only if there's demand; most clients ignore it for private CAs)

---

## Known limitations

- **Revocation is best-effort.** Chrome ignores custom CRLs, and Firefox and most TLS libraries don't fetch them by default. Short-lived certificates (Phase 3) are the real mitigation.
- **Server-held intermediate keys** are a target. Name constraints limit the blast radius, encryption limits the value of a database dump, and the offline root allows recovery by re-issuing intermediates.
