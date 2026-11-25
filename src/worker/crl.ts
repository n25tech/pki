import { Hono } from "hono";

/**
 * pki-crl host. URLs served here are embedded in issued certificates, so their
 * shape must never change:
 *
 *   /<ca-id>.crl   DER-encoded CRL       (application/pkix-crl)
 *   /<ca-id>.crt   DER-encoded CA cert   (application/pkix-cert)
 *
 * Served over HTTP and HTTPS without redirects; many CRL clients don't follow them.
 * Storage lookup arrives with the database work in Phase 1; until then every
 * CA id is unknown.
 */
export const crl = new Hono<{ Bindings: Env }>();

const CA_FILE = /^\/([a-z0-9][a-z0-9-]{0,63})\.(crl|crt)$/;

crl.get("/", (c) => c.text("pki.n25tech.com CRL and CA certificate distribution point\n"));

crl.get("*", (c) => {
  const match = CA_FILE.exec(new URL(c.req.url).pathname);
  if (!match) return c.text("Not found\n", 404);
  // TODO(phase 1): load the CRL / CA certificate for match[1] from storage.
  return c.text("Unknown CA\n", 404, { "Cache-Control": "public, max-age=60" });
});

crl.all("*", (c) => c.text("Method not allowed\n", 405, { Allow: "GET, HEAD" }));
