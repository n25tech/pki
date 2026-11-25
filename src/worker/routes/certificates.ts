import { Hono } from "hono";
import * as pki from "../../shared/pki";
import {
  type CaRow,
  type CertificateRow,
  certificateView,
  distributionUrls,
  getCa,
  loadCaKey,
  regenerateCrl,
} from "../lib/ca";
import type { AppEnv } from "../lib/context";
import { audit } from "../lib/services";
import { currentUser } from "../lib/session";
import { fail, now, randomId } from "../lib/util";
import { readJson } from "./json";

export const certificates = new Hono<AppEnv>();

const { x509 } = pki;

/** RFC 5280 reason codes offered for end-entity certificates. */
export const REVOCATION_REASONS: Record<number, string> = {
  0: "Unspecified",
  1: "Key compromise",
  3: "Affiliation changed",
  4: "Superseded",
  5: "Cessation of operation",
};

function cleanTags(tags: unknown): string[] {
  if (tags === undefined) return [];
  if (!Array.isArray(tags)) fail(400, "invalid_tags", "Tags must be a list");
  const out = [...new Set(tags.map((t) => String(t).trim().toLowerCase()).filter(Boolean))];
  if (out.length > 20 || out.some((t) => t.length > 40)) fail(400, "invalid_tags", "Up to 20 tags of 40 characters each");
  return out;
}

function cleanNotes(notes: unknown): string {
  const n = typeof notes === "string" ? notes : "";
  if (n.length > 2000) fail(400, "invalid_notes", "Notes must be at most 2000 characters");
  return n;
}

function cleanSans(input: unknown): pki.SubjectAltNames | null {
  if (!input || typeof input !== "object") return null;
  const { dns, ip } = input as { dns?: unknown; ip?: unknown };
  const list = (v: unknown) => (Array.isArray(v) ? v.map((x) => String(x).trim()).filter(Boolean) : []);
  const sans = { dns: list(dns), ip: list(ip) };
  if (sans.dns.length + sans.ip.length > 100) fail(400, "too_many_names", "At most 100 names per certificate");
  return sans.dns.length + sans.ip.length ? sans : null;
}

async function getCertificate(env: Env, userId: string, id: string): Promise<CertificateRow> {
  const row = await env.DB.prepare("SELECT * FROM certificates WHERE id = ? AND user_id = ?").bind(id, userId).first<CertificateRow>();
  if (!row) fail(404, "certificate_not_found", "Certificate not found");
  return row;
}

async function chainFor(env: Env, userId: string, caId: string): Promise<CaRow[]> {
  const chain: CaRow[] = [];
  let ca: CaRow | null = await getCa(env, userId, caId);
  while (ca) {
    chain.push(ca);
    ca = ca.parent_id ? await getCa(env, userId, ca.parent_id) : null;
  }
  return chain;
}

certificates.post("/", async (c) => {
  const user = currentUser(c);
  const b = await readJson<{
    caId: string;
    csrPem: string;
    commonName: string;
    sans: pki.SubjectAltNames;
    profile: pki.LeafProfile;
    validityDays: number;
    tags: string[];
    notes: string;
  }>(c);

  const ca = await getCa(c.env, user.id, String(b.caId ?? ""));
  if (ca.kind !== "intermediate") fail(400, "not_intermediate", "Certificates are issued by intermediate CAs");
  if (ca.revoked_at || !ca.key_enc) fail(400, "ca_revoked", "This intermediate is revoked");
  if (ca.not_after <= now()) fail(400, "ca_expired", "This intermediate has expired");
  const root = await getCa(c.env, user.id, ca.parent_id!);
  if (root.revoked_at) fail(400, "ca_revoked", "This intermediate's root is revoked");

  let csr: pki.x509.Pkcs10CertificateRequest;
  try {
    csr = await pki.parseCsr(String(b.csrPem ?? ""));
  } catch (e) {
    fail(400, "invalid_csr", e instanceof pki.PolicyError ? e.message : "Not a valid PKCS#10 certificate request");
  }
  const keyAlgorithm = pki.describePublicKey(csr.publicKey);
  if (!keyAlgorithm) fail(400, "unsupported_key", "Unsupported key: use ECDSA P-256/P-384 or RSA 2048–4096");

  const sans = cleanSans(b.sans) ?? pki.csrSubjectAltNames(csr);
  const commonName = (typeof b.commonName === "string" && b.commonName.trim()) || pki.csrCommonName(csr) || sans.dns[0] || sans.ip[0];
  if (!commonName || commonName.length > 64) fail(400, "invalid_common_name", "Common name is required (max 64 characters)");
  const profile = b.profile === "client" ? "client" : "server";
  const validityDays = Number(b.validityDays ?? 90);
  const tags = cleanTags(b.tags);
  const notes = cleanNotes(b.notes);

  const { crlUrl, certUrl } = distributionUrls(c.env, ca.id);
  let certificate: pki.x509.X509Certificate;
  try {
    ({ certificate } = await pki.issueLeaf({
      issuer: new x509.X509Certificate(ca.cert_pem),
      issuerKey: await loadCaKey(c.env, ca),
      constraints: JSON.parse(root.name_constraints!),
      publicKey: csr.publicKey,
      subject: { commonName },
      sans,
      profile,
      validityDays,
      crlUrl,
      issuerCertUrl: certUrl,
    }));
  } catch (e) {
    if (e instanceof pki.PolicyError) fail(400, "policy", e.message);
    throw e;
  }

  const id = randomId();
  await c.env.DB.prepare(
    `INSERT INTO certificates (id, user_id, ca_id, serial, common_name, sans, profile, key_algorithm,
                               not_before, not_after, fingerprint, cert_pem, tags, notes, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      user.id,
      ca.id,
      certificate.serialNumber,
      commonName,
      JSON.stringify(sans),
      profile,
      keyAlgorithm,
      certificate.notBefore.getTime(),
      certificate.notAfter.getTime(),
      await pki.fingerprint(certificate),
      certificate.toString("pem"),
      JSON.stringify(tags),
      notes,
      now(),
    )
    .run();
  await audit(c, user.id, "certificate.issued", id, { ca: ca.id, commonName, sans, profile, validityDays });
  const chain = await chainFor(c.env, user.id, ca.id);
  return c.json(
    { certificate: certificateView(await getCertificate(c.env, user.id, id)), chainPem: chain.map((x) => x.cert_pem) },
    201,
  );
});

certificates.get("/", async (c) => {
  const user = currentUser(c);
  const q = c.req.query();
  const where = ["user_id = ?"];
  const args: unknown[] = [user.id];
  const t = now();
  if (q.caId) {
    where.push("ca_id = ?");
    args.push(q.caId);
  }
  switch (q.status) {
    case "valid":
      where.push("revoked_at IS NULL AND not_after > ?");
      args.push(t);
      break;
    case "expiring":
      where.push("revoked_at IS NULL AND not_after > ? AND not_after < ?");
      args.push(t, t + 30 * 86_400_000);
      break;
    case "expired":
      where.push("revoked_at IS NULL AND not_after <= ?");
      args.push(t);
      break;
    case "revoked":
      where.push("revoked_at IS NOT NULL");
      break;
  }
  if (q.q) {
    const like = `%${q.q.replace(/[\\%_]/g, (ch) => `\\${ch}`).toLowerCase()}%`;
    where.push("(LOWER(common_name) LIKE ? ESCAPE '\\' OR LOWER(sans) LIKE ? ESCAPE '\\' OR LOWER(notes) LIKE ? ESCAPE '\\' OR serial LIKE ? ESCAPE '\\')");
    args.push(like, like, like, like);
  }
  if (q.tag) {
    where.push("EXISTS (SELECT 1 FROM json_each(certificates.tags) WHERE value = ?)");
    args.push(q.tag.toLowerCase());
  }
  const rows = await c.env.DB.prepare(
    `SELECT * FROM certificates WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT 500`,
  )
    .bind(...args)
    .all<CertificateRow>();
  return c.json({ certificates: rows.results.map(certificateView) });
});

certificates.get("/:id", async (c) => {
  const user = currentUser(c);
  const row = await getCertificate(c.env, user.id, c.req.param("id"));
  const chain = await chainFor(c.env, user.id, row.ca_id);
  return c.json({
    certificate: certificateView(row),
    chainPem: chain.map((x) => x.cert_pem),
    issuer: { id: chain[0].id, name: chain[0].name },
    root: { id: chain[chain.length - 1].id, name: chain[chain.length - 1].name },
  });
});

certificates.patch("/:id", async (c) => {
  const user = currentUser(c);
  const row = await getCertificate(c.env, user.id, c.req.param("id"));
  const b = await readJson<{ tags: string[]; notes: string }>(c);
  const tags = b.tags === undefined ? (JSON.parse(row.tags) as string[]) : cleanTags(b.tags);
  const notes = b.notes === undefined ? row.notes : cleanNotes(b.notes);
  await c.env.DB.prepare("UPDATE certificates SET tags = ?, notes = ? WHERE id = ?").bind(JSON.stringify(tags), notes, row.id).run();
  return c.json({ certificate: certificateView({ ...row, tags: JSON.stringify(tags), notes }) });
});

certificates.post("/:id/revoke", async (c) => {
  const user = currentUser(c);
  const row = await getCertificate(c.env, user.id, c.req.param("id"));
  if (row.revoked_at) fail(409, "already_revoked", "This certificate is already revoked");
  const b = await readJson<{ reason: number }>(c);
  const reason = Number(b.reason ?? 0);
  if (!(reason in REVOCATION_REASONS)) fail(400, "invalid_reason", "Unknown revocation reason");

  await c.env.DB.prepare("UPDATE certificates SET revoked_at = ?, revocation_reason = ? WHERE id = ? AND revoked_at IS NULL")
    .bind(now(), reason, row.id)
    .run();
  const ca = await getCa(c.env, user.id, row.ca_id);
  // Publish immediately. If the intermediate itself is revoked its key is gone, and its CRL can't change.
  if (ca.key_enc) await regenerateCrl(c.env, ca);
  await audit(c, user.id, "certificate.revoked", row.id, { reason, serial: row.serial });
  return c.json({ certificate: certificateView(await getCertificate(c.env, user.id, row.id)) });
});
