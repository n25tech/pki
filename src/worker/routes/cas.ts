/**
 * Certificate authorities.
 *
 * CA key pairs are generated in the browser (so the Worker never has to do
 * slow RSA key generation), then the private key is uploaded once and stored
 * encrypted. From then on the server signs with it: roots sign intermediates
 * and root CRLs, intermediates sign leaf certificates and their CRLs.
 */
import { Hono } from "hono";
import * as pki from "../../shared/pki";
import {
  type CaRow,
  caView,
  crlPem,
  distributionUrls,
  getCa,
  loadCaKey,
  regenerateCrl,
  sealCaKey,
} from "../lib/ca";
import type { AppEnv } from "../lib/context";
import { audit } from "../lib/services";
import { currentUser } from "../lib/session";
import { fail, now, randomId } from "../lib/util";
import { REVOCATION_REASONS } from "./certificates";
import { readJson } from "./json";

export const cas = new Hono<AppEnv>();

const { x509 } = pki;

const MAX_INTERMEDIATE_DAYS = 20 * 365;

function cleanName(name: unknown, fallback: string): string {
  const n = typeof name === "string" ? name.trim() : "";
  if (n.length > 64) fail(400, "invalid_name", "Name must be at most 64 characters");
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

/** Imports an uploaded PKCS#8 key and checks it belongs to `owner` (a certificate or CSR). */
async function importMatchingKey(pem: unknown, owner: { publicKey: pki.x509.PublicKey }): Promise<CryptoKey> {
  let key: CryptoKey;
  try {
    key = (await pki.importPrivateKeyAuto(String(pem ?? ""))).key;
  } catch (e) {
    fail(400, "invalid_key", (e as Error).message);
  }
  if (!(await pki.keyMatchesCertificate(key, owner))) fail(400, "key_mismatch", "The private key doesn't match");
  return key;
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
  return c.json({ ca: caView(ca), parent: parent ? caView(parent) : null, children: children.map(caView), crlPem: crlPem(ca) });
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

/** Registers a self-signed root (made in the browser) together with its private key. */
cas.post("/roots", async (c) => {
  const user = currentUser(c);
  const b = await readJson<{ name: string; certificatePem: string; privateKeyPem: string }>(c);
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
  const key = await importMatchingKey(b.privateKeyPem, cert);

  const id = randomId();
  const inserted = await c.env.DB.prepare(
    `INSERT INTO cas (id, user_id, kind, name, subject, serial, key_algorithm, not_before, not_after, fingerprint,
                      cert_pem, name_constraints, key_enc, created_at)
     VALUES (?, ?, 'root', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      await pki.fingerprint(cert),
      cert.toString("pem"),
      JSON.stringify(constraints),
      await sealCaKey(c.env, { id, user_id: user.id }, await pki.exportPrivateKey(key)),
      now(),
    )
    .first();
  if (!inserted) fail(409, "duplicate", "This root CA is already registered");

  await regenerateCrl(c.env, await getCa(c.env, user.id, id));
  await audit(c, user.id, "ca.root_created", id, { subject: cert.subject, constraints });
  return c.json({ ca: caView(await getCa(c.env, user.id, id)) }, 201);
});

// --- Intermediates ---------------------------------------------------------

/**
 * Creates an intermediate under a root. The browser generates the key pair and
 * sends a CSR (for the public key) plus the private key; the server signs the
 * certificate with the stored root key.
 */
cas.post("/intermediates", async (c) => {
  const user = currentUser(c);
  const b = await readJson<{ rootId: string; name: string; csrPem: string; privateKeyPem: string; validityDays: number }>(c);
  const root = await getCa(c.env, user.id, String(b.rootId ?? ""));
  if (root.kind !== "root") fail(400, "not_root", "Intermediates are created under a root CA");
  if (root.revoked_at || !root.key_enc) fail(400, "root_unavailable", "This root can't sign");
  if (root.not_after <= now()) fail(400, "root_expired", "This root has expired");

  let csr: pki.x509.Pkcs10CertificateRequest;
  try {
    csr = await pki.parseCsr(String(b.csrPem ?? ""));
  } catch {
    fail(400, "invalid_csr", "Not a valid certificate request");
  }
  const keyAlgorithm = pki.describePublicKey(csr.publicKey);
  if (!keyAlgorithm) fail(400, "unsupported_key", "Unsupported key algorithm");
  const key = await importMatchingKey(b.privateKeyPem, csr);
  const validityDays = Math.floor(Number(b.validityDays ?? 5 * 365));
  if (!(validityDays >= 1 && validityDays <= MAX_INTERMEDIATE_DAYS)) {
    fail(400, "invalid_validity", `Validity must be between 1 and ${MAX_INTERMEDIATE_DAYS} days`);
  }
  const name = cleanName(b.name, pki.csrCommonName(csr) ?? "Intermediate CA");

  const rootCert = new x509.X509Certificate(root.cert_pem);
  const { crlUrl, certUrl } = distributionUrls(c.env, root.id);
  const cert = await pki.signIntermediateCa({
    issuer: rootCert,
    issuerKey: await loadCaKey(c.env, root),
    subject: { commonName: name },
    publicKey: csr.publicKey,
    validityDays,
    crlUrl,
    issuerCertUrl: certUrl,
  });

  const id = randomId();
  await c.env.DB.prepare(
    `INSERT INTO cas (id, user_id, kind, parent_id, name, subject, serial, key_algorithm, not_before, not_after,
                      fingerprint, cert_pem, key_enc, created_at)
     VALUES (?, ?, 'intermediate', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      user.id,
      root.id,
      name,
      cert.subject,
      cert.serialNumber,
      keyAlgorithm,
      cert.notBefore.getTime(),
      cert.notAfter.getTime(),
      await pki.fingerprint(cert),
      cert.toString("pem"),
      await sealCaKey(c.env, { id, user_id: user.id }, await pki.exportPrivateKey(key)),
      now(),
    )
    .run();

  await regenerateCrl(c.env, await getCa(c.env, user.id, id));
  await audit(c, user.id, "ca.intermediate_created", id, { root: root.id, subject: cert.subject });
  return c.json({ ca: caView(await getCa(c.env, user.id, id)) }, 201);
});

/**
 * Revokes an intermediate: it's added to the root's CRL, it can no longer
 * issue, and its stored key is destroyed. Can't be undone.
 */
cas.post("/:id/revoke", async (c) => {
  const user = currentUser(c);
  const ca = await getCa(c.env, user.id, c.req.param("id"));
  if (ca.kind !== "intermediate") fail(400, "not_intermediate", "Only intermediate CAs can be revoked");
  if (ca.revoked_at) fail(409, "already_revoked", "This intermediate is already revoked");
  const b = await readJson<{ reason: number }>(c);
  const reason = Number(b.reason ?? 0);
  if (!(reason in REVOCATION_REASONS)) fail(400, "invalid_reason", "Unknown revocation reason");
  const root = await getCa(c.env, user.id, ca.parent_id!);
  if (!root.key_enc) fail(400, "root_unavailable", "The root's key isn't available to sign a CRL");

  // Publish a last CRL for the intermediate's own certificates while its key still exists.
  if (ca.key_enc) await regenerateCrl(c.env, ca);
  await c.env.DB.prepare(
    "UPDATE cas SET revoked_at = ?, revocation_reason = ?, key_enc = NULL WHERE id = ? AND revoked_at IS NULL",
  )
    .bind(now(), reason, ca.id)
    .run();
  await regenerateCrl(c.env, root);
  await audit(c, user.id, "ca.intermediate_revoked", ca.id, { root: root.id, reason });
  return c.json({ ca: caView(await getCa(c.env, user.id, ca.id)) });
});
