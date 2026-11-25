# pki.n25tech.com — Project Plan

A hosted private certificate authority for homelabs and teams running internal services without a public domain. Users create their own CA hierarchy, issue certificates, keep an inventory of what they issued, revoke individual certificates, and look up whether a certificate came from one of their CAs.

> **Disclaimer (shown in the app and README):** This is a convenience tool for labs and internal, non-critical use. It is not a hardened or production PKI. For anything with a real security requirement, use Let's Encrypt or a properly operated CA.

## Stack

- **Hosting:** a single Cloudflare Worker with static assets. It serves the React frontend (`src/web/`, built with Vite) and the API (`src/worker/`), and routes all three hostnames itself
- **Deploys:** Cloudflare Workers Builds on push to `master` (`npm run build`, then `npx wrangler deploy`)
- **Data (to add):** D1 (users, CAs, certificates, revocations, audit log), KV (cached CRLs)
- **Secrets:** Worker secrets (master wrapping key, OAuth secret, email API key, session secret)
- **Crypto:** WebCrypto + `@peculiar/x509` (`src/shared/pki.ts`, shared by browser and Worker), ECDSA P-256/P-384 by default, RSA 2048–4096 available

## Hostnames

| Purpose | Host | Notes |
|---|---|---|
| App + API | `pki.n25tech.com` | API at `/api/*` (same origin, no CORS); HTTP redirects to HTTPS |
| CRL / AIA | `pki-crl.n25tech.com` | Embedded in every certificate, so it must **never change**. Also served over plain HTTP (exempt from "Always Use HTTPS"). |
| ACME (Phase 3) | `pki-acme.n25tech.com` | Stable; goes into client configs |

Flat hostnames are covered by Cloudflare's free Universal SSL. Session cookies are host-only on `pki.n25tech.com` (no `Domain=.n25tech.com`). HSTS is sent without `includeSubDomains`, and must not be enabled zone-wide with `includeSubDomains`, or the CRL host breaks over HTTP.

## Security principles

1. **CA keys are stored server-side, encrypted.** Root and intermediate key pairs are generated in the browser (to keep RSA key generation off the Worker), then uploaded once and stored AES-GCM encrypted. The server signs intermediates, leaf certificates and all CRLs. Users can download a backup of the root key when creating it.
2. **Name constraints are mandatory** on every root (e.g. `.home.arpa`, `.lan`, `.internal`, a user-chosen suffix, RFC1918/ULA IP ranges), so a leaked key can't sign public domains. The server enforces this on every issuance, not just the UI.
3. **Key encryption** uses a key derived from `MASTER_KEY` (a Worker secret), bound to each CA's id and owner. A per-user passphrase layer could be added later.
4. **Leaf keys can be generated in the browser**, so the server only ever sees a CSR.
5. **2FA is mandatory** before any CA can be created. An account effectively *is* a CA.
6. **No secrets in git.** The repo is public, and all credentials live in Worker or GitHub Actions secrets.

---

## Phase 1 — MVP

### Foundations
- [x] Single-Worker project: Vite + `@cloudflare/vite-plugin`, React frontend, Hono API, shared TypeScript
- [x] Hostname routing for app / CRL / ACME hosts, with security headers on the app host
- [x] `.gitignore` (`.dev.vars`, `.env*`, key and cert files, `node_modules`, build output)
- [x] `SECURITY.md` with private vulnerability reporting; README with disclaimer
- [x] Licence: AGPL-3.0-only
- [x] CI: typecheck, tests (inside workerd), build and audit on PRs and `master`; Actions pinned to SHAs; no Cloudflare credentials in GitHub (Workers Builds deploys)
- [x] **Spike:** root, intermediate, leaf, CSR issuance, CRL and chain lookup with `@peculiar/x509` inside workerd (tests pass). Checked independently with OpenSSL: the chain verifies, a `google.com` cert signed by the same intermediate fails with "permitted subtree violation", and a revoked leaf is reported as revoked
- [x] D1 binding and migrations (KV turned out unnecessary: CRLs live in D1 and are edge-cached)
- [ ] Staging environment
- [ ] Measure RSA-4096 key generation CPU time on the deployed Worker

### Auth
- [x] Email/password, email verification, password reset. Hashing is PBKDF2-SHA256 at the Workers maximum of 100k iterations, plus an HMAC pepper derived from `MASTER_KEY`
- [x] Google OAuth (OIDC + PKCE); safe linking to unverified accounts
- [x] TOTP with replay protection and recovery codes; 2FA required before any CA work
- [ ] Passkeys (moved to Phase 2)
- [x] Sessions (HttpOnly, Secure, SameSite=Lax, `__Host-` cookie, hashed tokens), Origin-checked writes, rate limiting
- [x] Audit log of security-relevant events

### CA core
- [x] Root generation (key pair made in the browser) with a required name-constraints editor; root key stored encrypted, optional backup download
- [x] Intermediates: key pair made in the browser and sent with a CSR; the server signs it with the stored root key and stores the intermediate key encrypted
- [x] Multiple intermediates per root (per site or environment)
- [x] CA detail pages: subject, validity, constraints, fingerprints, chain download

### Certificates & inventory
- [x] Issue from a browser-generated key, or from a pasted CSR
- [x] Profiles: TLS server, TLS client; SAN editor (DNS + IP)
- [x] Server-side policy: reject anything outside the root's name constraints
- [x] Exports: PEM, full chain, root, Kubernetes secret YAML. PKCS#12 is an `openssl` one-liner in the UI for now
- [x] Inventory: search, filter by CA, expiry status, tags, notes

### Revocation & lookup
- [x] Revoke with a reason code; inventory updates immediately
- [x] Per-CA CRL at `pki-crl.n25tech.com/<ca-id>.crl`, regenerated on revocation and by a daily cron
- [x] Root CRLs signed by the server; revoking an intermediate lists it on the root CRL and destroys its stored key
- [x] Lookup by pasting or uploading a certificate: verify the chain and report the issuing CA and status (valid / revoked / expired / unknown)

### Pre-launch
- [x] Trust-store install guides: Windows, macOS, Linux (Debian/Ubuntu, Fedora/RHEL, Arch), iOS, Android, Firefox, Java keystore, Docker, Node/Python/curl
- [x] Disclaimer, terms, privacy page (rewritten with providers, cookies, retention and contact; still needs review)
- [x] Cloudflare Turnstile on sign-up and password-reset requests
- [x] Account export (CAs + intermediate keys + inventory) and account deletion that destroys stored keys
- [x] CSP, security headers, dependency audit in CI
- [ ] Set `MASTER_KEY` (and optionally Google and Resend secrets) in production

## Phase 2 — Day-to-day usability
- [ ] Passkeys (WebAuthn) as a second factor
- [ ] PKCS#12 export in the browser
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
- **Server-held CA keys** (roots and intermediates) are a target. Name constraints limit what a stolen key can sign, and encryption with a key that lives only in Worker secrets makes a database dump alone useless. A compromise of the Worker itself would expose every CA key, which is the trade-off for not needing the root key on hand to create or revoke intermediates.
