import { Hono } from "hono";
import { type CaRow, crlBytes, regenerateIntermediateCrl } from "./lib/ca";
import { now } from "./lib/util";
import * as pki from "../shared/pki";

/**
 * pki-crl host. URLs served here are embedded in issued certificates, so their
 * shape must never change:
 *
 *   /<ca-id>.crl   DER-encoded CRL       (application/pkix-crl)
 *   /<ca-id>.crt   DER-encoded CA cert   (application/pkix-cert)
 *
 * Served over HTTP and HTTPS without redirects; many CRL clients don't follow them.
 */
export const crl = new Hono<{ Bindings: Env }>();

const CA_FILE = /^\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(crl|crt)$/;
const CACHE_SECONDS = 300;

crl.get("/", (c) => c.text("pki.n25tech.com CRL and CA certificate distribution point\n"));

crl.get("*", async (c) => {
  const match = CA_FILE.exec(new URL(c.req.url).pathname);
  if (!match) return c.text("Not found\n", 404);
  const [, id, ext] = match;
  const ca = await c.env.DB.prepare("SELECT * FROM cas WHERE id = ?").bind(id).first<CaRow>();
  if (!ca) return c.text("Unknown CA\n", 404, { "Cache-Control": "public, max-age=60" });

  if (ext === "crt") {
    const der = pki.x509.PemConverter.decodeFirst(ca.cert_pem);
    return c.body(der, 200, {
      "Content-Type": "application/pkix-cert",
      "Cache-Control": "public, max-age=86400",
    });
  }

  let der = crlBytes(ca);
  // Intermediate CRLs are kept fresh here too, in case the daily cron missed one.
  if (ca.kind === "intermediate" && ca.key_enc && (!der || (ca.crl_next_update ?? 0) < now() + 24 * 3600_000)) {
    der = await regenerateIntermediateCrl(c.env, ca);
  }
  if (!der) return c.text("No CRL published\n", 404);
  return c.body(der.slice().buffer, 200, {
    "Content-Type": "application/pkix-crl",
    "Cache-Control": `public, max-age=${CACHE_SECONDS}`,
  });
});

crl.all("*", (c) => c.text("Method not allowed\n", 405, { Allow: "GET, HEAD" }));

