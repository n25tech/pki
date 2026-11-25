# pki.n25tech.com

A hosted private certificate authority for homelabs and internal services that
don't have a public domain. Create your own CA, issue certificates, keep track
of what you issued, revoke individual certificates, and check whether a
certificate came from one of your CAs.

> **Not for production.** This is a convenience tool for labs and internal,
> non-critical use. It is not a hardened or production PKI. For anything with a
> real security requirement, use [Let's Encrypt](https://letsencrypt.org/) or a
> properly operated CA.

## How it protects you

- **Every root is name-constrained** to private names (e.g. `.home.arpa`,
  `.lan`, private IP ranges). Even if a key leaked, it couldn't be used to
  impersonate public websites.
- **CA keys are stored encrypted.** Root and intermediate keys are generated in
  your browser, then stored AES-GCM encrypted with a key held only in the
  Worker's secrets, so the service can sign intermediates, certificates and
  CRLs for you.
- **Certificate keys can stay with you.** Keys for end-entity certificates are
  generated in your browser (or you bring a CSR) and are never uploaded.
- **Two-factor authentication is required** before you can create a CA.

See [PLAN.md](PLAN.md) for the full design and roadmap.

## Architecture

A single Cloudflare Worker serves everything, routing by hostname:

| Host | Serves |
|---|---|
| `pki.n25tech.com` | Web app (static assets) and JSON API under `/api/*` |
| `pki-crl.n25tech.com` | CRLs and CA certificates (HTTP and HTTPS; URLs are embedded in certificates and never change) |
| `pki-acme.n25tech.com` | ACME server (planned) |

```
src/
  shared/pki.ts   CA primitives (WebCrypto + @peculiar/x509), used by browser and Worker
  worker/         Worker entry, hostname router, API / CRL / ACME handlers
  web/            React frontend (Vite)
test/             Vitest tests, run inside workerd
```

## Development

Requires Node.js 22+.

```sh
npm install
cp .dev.vars.example .dev.vars            # then set MASTER_KEY=$(openssl rand -base64 32)
CI=1 npx wrangler d1 migrations apply DB --local
npm run dev        # Vite dev server with the Worker running in workerd
npm test           # tests in the Workers runtime, against a local D1
npm run typecheck
npm run build
```

Without `RESEND_API_KEY`, verification and password-reset emails are printed
to the Worker log instead of being sent.

On `localhost` and `*.workers.dev` preview URLs, the app is served at the root
and the CRL and ACME hosts are reachable under `/_crl/*` and `/_acme/*`.

After changing `wrangler.jsonc`, regenerate binding types with
`npm run cf-typegen`.

## Deployment

Cloudflare Workers Builds deploys on push to `master`:

- Build command: `npm run build`
- Deploy command: `npx wrangler deploy`

The D1 database is created automatically on the first deploy.

### Database migrations

Migrations in `migrations/` are applied **manually**, not by the deploy:

```sh
npx wrangler d1 migrations list DB --remote    # what's pending
npx wrangler d1 migrations apply DB --remote   # apply it
```

When a pull request adds a migration, decide the order:

- **Additive changes** (new tables or nullable columns): apply the migration
  *before* merging, so the new code finds the schema it expects.
- **Destructive changes** (dropping or renaming): merge and deploy code that no
  longer uses the old schema first, then apply the migration.

Never edit a migration that has already been applied; add a new one.

### Secrets

Set these in the Worker's settings (or with `npx wrangler secret put <NAME>`):

| Secret | Required | Purpose |
|---|---|---|
| `MASTER_KEY` | yes | 32 random bytes, base64 (`openssl rand -base64 32`). Encrypts CA private keys and TOTP secrets, and peppers password hashes. **Back it up**: losing it makes every stored CA key and 2FA enrolment unusable. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | no | Google sign-in. Redirect URI: `https://pki.n25tech.com/api/auth/google/callback` |
| `RESEND_API_KEY` | no | Sends verification and password-reset emails from `EMAIL_FROM` (verify the n25tech.com domain in Resend). |
| `TURNSTILE_SECRET_KEY` | no | Cloudflare Turnstile secret. With `TURNSTILE_SITE_KEY` set in `wrangler.jsonc`, sign-up and password-reset requests require passing Turnstile's human check. |

The app returns errors for sign-up and sign-in until `MASTER_KEY` is set.

### Turnstile (bot protection)

The widget's public site key is in `wrangler.jsonc` (`vars.TURNSTILE_SITE_KEY`), and tokens are only accepted
when issued on a hostname listed in `vars.TURNSTILE_HOSTNAMES` (`pki.n25tech.com`).

To enforce it, set the widget's **secret key** (Cloudflare dashboard → Turnstile → the widget → Settings):

```sh
npx wrangler secret put TURNSTILE_SECRET_KEY
```

The check is only enforced when both the site key and the secret are set. Locally, leave `TURNSTILE_SECRET_KEY` out of `.dev.vars`
and the check stays off.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Licence

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only). You may use, modify and self-host it.
If you run a modified version as a network service, you must make your changes available to its users under
the same licence.
