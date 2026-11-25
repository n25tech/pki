# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/n25tech/pki/security/advisories/new).
Include what you found, how to reproduce it, and the impact you expect.

You should get an acknowledgement within a few days. Once a fix is available
we'll credit you in the advisory unless you'd rather stay anonymous.

## Scope

In scope: the code in this repository and the hosted service at
`pki.n25tech.com`, `pki-crl.n25tech.com` and `pki-acme.n25tech.com`.

Of particular interest:

- Anything that lets one account read, use or influence another account's CAs,
  keys or certificates
- Ways to obtain certificates outside a CA's name constraints
- Exposure of stored CA private keys (roots or intermediates)
- Authentication or session bypasses

## Not a production PKI

This service is intended for labs and internal, non-critical use. See the
disclaimer in the README.
