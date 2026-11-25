/**
 * Certificate authorities.
 *
 * Roots are created in the browser; the server only ever receives the root
 * certificate and root-signed CRLs, never the root key. Intermediates are
 * signed by the root in the browser, then the intermediate's key is uploaded
 * once, encrypted, and used by the server to sign leaf certificates and CRLs.
 */
import { Hono } from "hono";
import * as pki from "../../shared/pki";
import {
  type CaRow,
  caView,
  crlPem,
  getCa,
  regenerateIntermediateCrl,
  sealCaKey,
} from "../lib/ca";
import type { AppEnv } from "../lib/context";
import { audit } from "../lib/services";
import { currentUser } from "../lib/session";
import { fail, now, randomId, toBase64 } from "../lib/util";
import { readJson } from "./json";

export const cas = new Hono<AppEnv>();

const { x509 } = pki;

function cleanName(name: unknown, fallback: string): string {
  const n = typeof name === "string" ? name.trim() : "";
  if (n.length > 100) fail(400, "invalid_name", "Name must be at most 100 characters");
  return n || fallback;
}

function isCa(cert: pki.x509.X509Certificate, pathLength: number | null): boolean {
  const bc = cert.getExtension(x509.BasicConstraintsExtension);
  const ku = cert.getExtension(x509.KeyUsagesExtension);
  if (!bc?.ca || !ku || !(ku.usages & x509.KeyUsageFlags.keyCertSign) || !(ku.usages & x509.KeyUsageFlags.cRLSign)) {
    return false;
  }
  return pathLength === null || bc.pathLength === pathLength;
}

function sameName(a: pki.x509.Name, b: pki.x509.Name): boolean {
  return a.toString() === b.toString();
}

cas.get("/", async (c) => {
  const user = currentUser(c);
  const rows = await c.env.DB.prepare("SELECT * FROM cas WHERE user_id = ? ORDER BY created_at").bind(user.id).all<CaRow>();
  const counts = await c.env.DB.prepare(
    `SELECT ca_id, COUNT(*) AS total, SUM(revoked_at IS NULL AND not_after > ?) AS active
     FROM certificates WHERE user_id = ? GROUP BY ca_id`,
  )
    .bind(now(), user.id)
    .all<{ ca_id: string; total: number; active: number }>();
  const byCa = new Map(counts.results.map((r) => [r.ca_id, r]));
  return c.json({
    cas: rows.results.map((ca) => ({
      ...caView(ca),
      certificates: { total: byCa.get(ca.id)?.total ?? 0, active: byCa.get(ca.id)?.active ?? 0 },
    })),
  });
});

cas.get("/:id", async (c) => {
  const user = currentUser(c);
  const ca = await getCa(c.env, user.id, c.req.param("id"));
  const parent = ca.parent_id ? await getCa(c.env, user.id, ca.parent_id) : null;
  const children =
    ca.kind === "root"
      ? (await c.env.DB.prepare("SELECT * FROM cas WHERE parent_id = ? ORDER BY created_at").bind(ca.id).all<CaRow>()).results
      : [];
  return c.json({
    ca: caView(ca),
    parent: parent ? caView(parent) : null,
    children: children.map(caView),
    // Root CRL, so the browser can extend it when revoking an intermediate.
    crlPem: crlPem(ca),
  });
});

cas.patch("/:id", async (c) => {
  const user = currentUser(c);
  const ca = await getCa(c.env, user.id, c.req.param("id"));
  const b = await readJson<{ name: string }>(c);
  const name = cleanName(b.name, ca.name);
  await c.env.DB.prepare("UPDATE cas SET name = ? WHERE id = ?").bind(name, ca.id).run();
  await audit(c, user.id, "ca.renamed", ca.id, { name });
  return c.json({ ca: caView({ ...ca, name }) });
});

// --- Roots -----------------------------------------------------------------

cas.post("/roots", async (c) => {
  const user = currentUser(c);
  const b = await readJson<{ name: string; certificatePem: string; crlPem: string }>(c);
  const cert = pki.parseCertificate(String(b.certificatePem ?? ""));

  if (!(await cert.isSelfSigned())) fail(400, "not_self_signed", "A root certificate must be self-signed");
  if (!isCa(cert, null)) fail(400, "not_a_ca", "The certificate isn't a CA (needs basicConstraints CA and keyCertSign/cRLSign)");
  const constraints = pki.readNameConstraints(cert);
  if (!constraints) fail(400, "no_name_constraints", "Root CAs must have name constraints");
  try {
    pki.validateNameConstraints(constraints);
  } catch (e) {
    fail(400, "invalid_name_constraints", (e as Error).message);
  }
  if (cert.notAfter.getTime() <= now()) fail(400, "expired", "This certificate has expired");
  const keyAlgorithm = pki.describePublicKey(cert.publicKey);
  if (!keyAlgorithm) fail(400, "unsupported_key", "Unsupported key algorithm");

  const crl = pki.parseCrl(String(b.crlPem ?? ""));
  if (!sameName(crl.issuerName, cert.subjectName) || !(await crl.verify({ publicKey: cert.publicKey }))) {
    fail(400, "invalid_crl", "The CRL must be signed by this root");
  }

  const id = randomId();
  const fingerprint = await pki.fingerprint(cert);
  const inserted = await c.env.DB.prepare(
    `INSERT INTO cas (id, user_id, kind, name, subject, serial, key_algorithm, not_before, not_after, fingerprint,
                      cert_pem, name_constraints, crl_der, crl_number, crl_next_update, created_at)
     VALUES (?, ?, 'root', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, fingerprint) DO NOTHING RETURNING id`,
  )
    .bind(
      id,
      user.id,
      cleanName(b.name, cert.subjectName.getField("CN")[0] ?? "Root CA"),
      cert.subject,
      cert.serialNumber,
      keyAlgorithm,
      cert.notBefore.getTime(),
      cert.notAfter.getTime(),
      fingerprint,
      cert.toString("pem"),
      JSON.stringify(constraints),
      toBase64(crl.rawData),
      pki.crlNumberOf(crl) ?? 0,
      crl.nextUpdate?.getTime() ?? null,
      now(),
    )
    .first();
  if (!inserted) fail(409, "duplicate", "This root CA is already registered");
  await audit(c, user.id, "ca.root_created", id, { subject: cert.subject, constraints });
  return c.json({ ca: caView((await getCa(c.env, user.id, id))!) }, 201);
});

/**
 * Replaces a root's CRL with a newer one signed (in the browser) by the root key.
 * Serials on the CRL that belong to this root's intermediates mark them revoked.
 */
cas.put("/:id/crl", async (c) => {
  const user = currentUser(c);
  const root = await getCa(c.env, user.id, c.req.param("id"));
  if (root.kind !== "root") fail(400, "not_root", "Only root CRLs are uploaded; intermediate CRLs are generated automatically");
  const b = await readJson<{ crlPem: string }>(c);
  const cert = new x509.X509Certificate(root.cert_pem);
  const crl = pki.parseCrl(String(b.crlPem ?? ""));
  if (!sameName(crl.issuerName, cert.subjectName) || !(await crl.verify({ publicKey: cert.publicKey }))) {
    fail(400, "invalid_crl", "The CRL must be signed by this root");
  }
  const number = pki.crlNumberOf(crl);
  if (number === null || number <= root.crl_number) {
    fail(400, "stale_crl", `The CRL number must be greater than ${root.crl_number}`);
  }

  const children = (await c.env.DB.prepare("SELECT * FROM cas WHERE parent_id = ?").bind(root.id).all<CaRow>()).results;
  const entries = new Map(crl.entries.map((e) => [e.serialNumber.toLowerCase(), e]));
  for (const child of children) {
    if (child.revoked_at && !entries.has(child.serial.toLowerCase())) {
      fail(400, "unrevoke_not_supported", `Intermediate "${child.name}" was revoked and must stay on the CRL`);
    }
  }
  const newlyRevoked = children.filter((ch) => !ch.revoked_at && entries.has(ch.serial.toLowerCase()));

  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE cas SET crl_der = ?, crl_number = ?, crl_next_update = ? WHERE id = ? AND crl_number = ?").bind(
      toBase64(crl.rawData),
      number,
      crl.nextUpdate?.getTime() ?? null,
      root.id,
      root.crl_number,
    ),
    // A revoked intermediate can't issue anything again, so its key is destroyed.
    ...newlyRevoked.map((ch) => {
      const e = entries.get(ch.serial.toLowerCase())!;
      return c.env.DB.prepare("UPDATE cas SET revoked_at = ?, revocation_reason = ?, key_enc = NULL WHERE id = ?").bind(
        e.revocationDate.getTime(),
        e.reason ?? 0,
        ch.id,
      );
    }),
  ]);
  for (const ch of newlyRevoked) await audit(c, user.id, "ca.intermediate_revoked", ch.id, { root: root.id });
  await audit(c, user.id, "ca.root_crl_updated", root.id, { crlNumber: number });
  return c.json({ ca: caView((await getCa(c.env, user.id, root.id))!), revoked: newlyRevoked.map((ch) => ch.id) });
});

// --- Intermediates ---------------------------------------------------------

cas.post("/intermediates", async (c) => {
  const user = currentUser(c);
  const b = await readJson<{ rootId: string; name: string; certificatePem: string; privateKeyPem: string }>(c);
  const root = await getCa(c.env, user.id, String(b.rootId ?? ""));
  if (root.kind !== "root") fail(400, "not_root", "Intermediates must be signed by a root CA");
  if (root.revoked_at) fail(400, "root_revoked", "This root is revoked");
  const rootCert = new x509.X509Certificate(root.cert_pem);

  const cert = pki.parseCertificate(String(b.certificatePem ?? ""));
  if (!sameName(cert.issuerName, rootCert.subjectName) || !(await cert.verify({ publicKey: rootCert.publicKey, signatureOnly: true }))) {
    fail(400, "not_signed_by_root", "The intermediate certificate isn't signed by this root");
  }
  if (!isCa(cert, 0)) fail(400, "not_a_ca", "The certificate must be a CA with path length 0");
  if (cert.notAfter.getTime() <= now()) fail(400, "expired", "This certificate has expired");
  const keyAlgorithm = pki.describePublicKey(cert.publicKey);
  if (!keyAlgorithm) fail(400, "unsupported_key", "Unsupported key algorithm");

  let key: CryptoKey;
  try {
    key = (await pki.importPrivateKeyAuto(String(b.privateKeyPem ?? ""))).key;
  } catch (e) {
    fail(400, "invalid_key", (e as Error).message);
  }
  if (!(await pki.keyMatchesCertificate(key, cert))) fail(400, "key_mismatch", "The private key doesn't match the certificate");

  const id = randomId();
  const pkcs8 = await pki.exportPrivateKey(key);
  const inserted = await c.env.DB.prepare(
    `INSERT INTO cas (id, user_id, kind, parent_id, name, subject, serial, key_algorithm, not_before, not_after,
                      fingerprint, cert_pem, key_enc, created_at)
     VALUES (?, ?, 'intermediate', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, fingerprint) DO NOTHING RETURNING id`,
  )
    .bind(
      id,
      user.id,
      root.id,
      cleanName(b.name, cert.subjectName.getField("CN")[0] ?? "Intermediate CA"),
      cert.subject,
      cert.serialNumber,
      keyAlgorithm,
      cert.notBefore.getTime(),
      cert.notAfter.getTime(),
      await pki.fingerprint(cert),
      cert.toString("pem"),
      await sealCaKey(c.env, { id, user_id: user.id }, pkcs8),
      now(),
    )
    .first();
  if (!inserted) fail(409, "duplicate", "This intermediate is already registered");

  const ca = await getCa(c.env, user.id, id);
  await regenerateIntermediateCrl(c.env, ca);
  await audit(c, user.id, "ca.intermediate_created", id, { root: root.id, subject: cert.subject });
  return c.json({ ca: caView(await getCa(c.env, user.id, id)) }, 201);
});
