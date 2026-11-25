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

- **Your root key never reaches the server.** Roots are generated in your
  browser and you keep the key.
- **Every root is name-constrained** to private names (e.g. `.home.arpa`,
  `.lan`, private IP ranges). Even if a key leaked, it couldn't be used to
  impersonate public websites.
- **Intermediate keys are stored encrypted**, and can be replaced by re-signing
  from your offline root.

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
npm run dev        # Vite dev server with the Worker running in workerd
npm test           # tests in the Workers runtime
npm run typecheck
npm run build
```

On `localhost` and `*.workers.dev` preview URLs, the app is served at the root
and the CRL and ACME hosts are reachable under `/_crl/*` and `/_acme/*`.

After changing `wrangler.jsonc`, regenerate binding types with
`npm run cf-typegen`.

## Deployment

Cloudflare Workers Builds deploys on push to `master` (build: `npm run build`,
deploy: `npx wrangler deploy`). Secrets are set with `wrangler secret put` and
are never committed.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).
