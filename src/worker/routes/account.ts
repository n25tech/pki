import { Hono } from "hono";
import * as pki from "../../shared/pki";
import { type CaRow, type CertificateRow, caView, certificateStatus, crlPem, certificateView, loadCaKey } from "../lib/ca";
import type { AppEnv } from "../lib/context";
import { audit } from "../lib/services";
import { currentUser, destroySession } from "../lib/session";
import { fail, now } from "../lib/util";
import { readJson } from "./json";

export const account = new Hono<AppEnv>();
export const lookup = new Hono<AppEnv>();

const { x509 } = pki;

/**
 * Checks whether a certificate was issued by one of the user's CAs.
 * Matches by exact fingerprint first, then by verifying the signature chain.
 */
lookup.post("/", async (c) => {
  const user = currentUser(c);
  const b = await readJson<{ certificatePem: string }>(c);
  const cert = pki.parseCertificate(String(b.certificatePem ?? ""));
  const fp = await pki.fingerprint(cert);

  const caRows = (await c.env.DB.prepare("SELECT * FROM cas WHERE user_id = ?").bind(user.id).all<CaRow>()).results;
  const ownCa = caRows.find((ca) => ca.fingerprint === fp);
  if (ownCa) return c.json({ result: "ca", ca: caView(ownCa) });

  const record = await c.env.DB.prepare("SELECT * FROM certificates WHERE user_id = ? AND fingerprint = ?")
    .bind(user.id, fp)
    .first<CertificateRow>();

  const found = await pki.findIssuingChain(cert, caRows.map((ca) => new x509.X509Certificate(ca.cert_pem)));
  if (found.status !== "issued") {
    return c.json({ result: "unknown", subject: cert.subject, issuer: cert.issuer, serial: cert.serialNumber, fingerprint: fp });
  }
  const chainFps = await Promise.all(found.chain.slice(1).map((x) => pki.fingerprint(x)));
  const chainCas = chainFps.map((f) => caRows.find((ca) => ca.fingerprint === f)!);
  const issuer = chainCas[0];
  // Status from the issuer's records, even if this exact certificate isn't in the inventory.
  const bySerial =
    record ??
    (await c.env.DB.prepare("SELECT * FROM certificates WHERE ca_id = ? AND serial = ?").bind(issuer.id, cert.serialNumber).first<CertificateRow>());
  const revokedCa = chainCas.find((ca) => ca.revoked_at);
  return c.json({
    result: "issued",
    subject: cert.subject,
    serial: cert.serialNumber,
    fingerprint: fp,
    notAfter: cert.notAfter.getTime(),
    status: revokedCa ? "revoked" : certificateStatus({ revoked_at: bySerial?.revoked_at ?? null, not_after: cert.notAfter.getTime() }),
    revokedVia: revokedCa ? { id: revokedCa.id, name: revokedCa.name } : null,
    chain: chainCas.map((ca) => ({ id: ca.id, name: ca.name, kind: ca.kind })),
    certificate: bySerial ? certificateView(bySerial) : null,
  });
});

account.get("/audit", async (c) => {
  const user = currentUser(c);
  const before = Number(c.req.query("before") ?? Number.MAX_SAFE_INTEGER);
  const rows = await c.env.DB.prepare(
    "SELECT id, action, target, meta, ip, created_at FROM audit_log WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT 100",
  )
    .bind(user.id, before)
    .all<{ id: number; action: string; target: string | null; meta: string | null; ip: string; created_at: number }>();
  return c.json({
    events: rows.results.map((r) => ({ ...r, meta: r.meta ? JSON.parse(r.meta) : null })),
  });
});

/**
 * Everything needed to leave: CA certificates, CA private keys
 * (decrypted) for roots and intermediates, the inventory and the CRLs.
 */
account.get("/export", async (c) => {
  const user = currentUser(c);
  const caRows = (await c.env.DB.prepare("SELECT * FROM cas WHERE user_id = ? ORDER BY created_at").bind(user.id).all<CaRow>()).results;
  const certRows = (
    await c.env.DB.prepare("SELECT * FROM certificates WHERE user_id = ? ORDER BY created_at").bind(user.id).all<CertificateRow>()
  ).results;
  const exported = await Promise.all(
    caRows.map(async (ca) => ({
      ...caView(ca),
      privateKeyPem: ca.key_enc ? pki.privateKeyToPem(await pki.exportPrivateKey(await loadCaKey(c.env, ca))) : null,
      crlPem: crlPem(ca),
    })),
  );
  await audit(c, user.id, "account.exported");
  return c.json(
    { exportedAt: now(), account: { email: user.email }, cas: exported, certificates: certRows.map(certificateView) },
    200,
    { "Content-Disposition": 'attachment; filename="pki-export.json"', "Cache-Control": "no-store" },
  );
});

/** Deletes the account and, by cascade, every CA, stored key and certificate record. */
account.delete("/", async (c) => {
  const user = currentUser(c);
  const b = await readJson<{ confirmEmail: string }>(c);
  if (String(b.confirmEmail ?? "").trim().toLowerCase() !== user.email.toLowerCase()) {
    fail(400, "confirmation_mismatch", "Type your email address to confirm");
  }
  await destroySession(c);
  await c.env.DB.prepare("DELETE FROM users WHERE id = ?").bind(user.id).run();
  console.log(`account deleted: ${user.id}`);
  return c.json({ ok: true });
});
