import * as pki from "../../shared/pki";
import { seal, unseal } from "./secrets";
import { fail, fromBase64, now, toBase64 } from "./util";

export interface CaRow {
  id: string;
  user_id: string;
  kind: "root" | "intermediate";
  parent_id: string | null;
  name: string;
  subject: string;
  serial: string;
  key_algorithm: string;
  not_before: number;
  not_after: number;
  fingerprint: string;
  cert_pem: string;
  name_constraints: string | null;
  key_enc: string | null;
  crl_der: string | null;
  crl_number: number;
  crl_next_update: number | null;
  revoked_at: number | null;
  revocation_reason: number | null;
  created_at: number;
}

export interface CertificateRow {
  id: string;
  user_id: string;
  ca_id: string;
  serial: string;
  common_name: string;
  sans: string;
  profile: "server" | "client";
  key_algorithm: string;
  not_before: number;
  not_after: number;
  fingerprint: string;
  cert_pem: string;
  tags: string;
  notes: string;
  revoked_at: number | null;
  revocation_reason: number | null;
  created_at: number;
}

/** CRLs are valid for a week and refreshed daily when within 3 days of expiry. */
export const CRL_VALIDITY_HOURS = 24 * 7;
export const CRL_REFRESH_WINDOW_MS = 3 * 24 * 3600_000;

/** Public URLs embedded in certificates. These must never change. */
export function distributionUrls(env: Env, caId: string) {
  return {
    crlUrl: `http://${env.CRL_HOST}/${caId}.crl`,
    certUrl: `http://${env.CRL_HOST}/${caId}.crt`,
  };
}

export async function getCa(env: Env, userId: string, id: string): Promise<CaRow> {
  const ca = await env.DB.prepare("SELECT * FROM cas WHERE id = ? AND user_id = ?").bind(id, userId).first<CaRow>();
  if (!ca) fail(404, "ca_not_found", "CA not found");
  return ca;
}

function keyContext(ca: Pick<CaRow, "id" | "user_id">) {
  return `ca:${ca.id}:${ca.user_id}`;
}

export async function sealCaKey(env: Env, ca: Pick<CaRow, "id" | "user_id">, pkcs8: ArrayBuffer): Promise<string> {
  return seal(env, new Uint8Array(pkcs8), keyContext(ca));
}

export async function loadCaKey(env: Env, ca: CaRow): Promise<CryptoKey> {
  if (!ca.key_enc) throw new Error(`CA ${ca.id} has no stored key`);
  const der = await unseal(env, ca.key_enc, keyContext(ca));
  return pki.importPrivateKey(der.buffer as ArrayBuffer, ca.key_algorithm as pki.KeyAlgorithm);
}

/**
 * Signs and stores a fresh CRL for a CA whose key is stored.
 * Root CRLs list revoked intermediates; intermediate CRLs list revoked leaves.
 */
export async function regenerateCrl(env: Env, ca: CaRow): Promise<Uint8Array> {
  const key = await loadCaKey(env, ca);
  const revoked =
    ca.kind === "root"
      ? await env.DB.prepare(
          "SELECT serial, revoked_at, revocation_reason FROM cas WHERE parent_id = ? AND revoked_at IS NOT NULL",
        )
          .bind(ca.id)
          .all<{ serial: string; revoked_at: number; revocation_reason: number | null }>()
      : await env.DB.prepare(
          "SELECT serial, revoked_at, revocation_reason FROM certificates WHERE ca_id = ? AND revoked_at IS NOT NULL",
        )
          .bind(ca.id)
          .all<{ serial: string; revoked_at: number; revocation_reason: number | null }>();
  const number = ca.crl_number + 1;
  const crl = await pki.createCrl({
    issuer: new pki.x509.X509Certificate(ca.cert_pem),
    issuerKey: key,
    crlNumber: number,
    validityHours: CRL_VALIDITY_HOURS,
    entries: revoked.results.map((r) => ({
      serialNumber: r.serial,
      revokedAt: new Date(r.revoked_at),
      reason: r.revocation_reason ?? undefined,
    })),
  });
  const der = new Uint8Array(crl.rawData);
  // Only write if nobody else bumped the number meanwhile; numbers must increase.
  await env.DB.prepare(
    "UPDATE cas SET crl_der = ?, crl_number = ?, crl_next_update = ? WHERE id = ? AND crl_number = ?",
  )
    .bind(toBase64(der), number, crl.nextUpdate!.getTime(), ca.id, ca.crl_number)
    .run();
  return der;
}

/** Refreshes CRLs that expire soon. Run from the cron trigger. */
export async function refreshExpiringCrls(env: Env): Promise<number> {
  const due = await env.DB.prepare(
    `SELECT * FROM cas WHERE key_enc IS NOT NULL
       AND (crl_next_update IS NULL OR crl_next_update < ?) LIMIT 200`,
  )
    .bind(now() + CRL_REFRESH_WINDOW_MS)
    .all<CaRow>();
  for (const ca of due.results) {
    try {
      await regenerateCrl(env, ca);
    } catch (err) {
      console.error(`CRL refresh failed for ${ca.id}`, err);
    }
  }
  return due.results.length;
}

export function crlBytes(ca: CaRow): Uint8Array | null {
  return ca.crl_der ? fromBase64(ca.crl_der) : null;
}

export function crlPem(ca: CaRow): string | null {
  const der = crlBytes(ca);
  return der ? pki.x509.PemConverter.encode(der.slice().buffer, "X509 CRL") : null;
}

export function sansOf(row: Pick<CertificateRow, "sans">): pki.SubjectAltNames {
  return JSON.parse(row.sans) as pki.SubjectAltNames;
}

export function certificateStatus(row: { revoked_at: number | null; not_after: number }, t = now()) {
  if (row.revoked_at) return "revoked" as const;
  if (row.not_after < t) return "expired" as const;
  return "valid" as const;
}

export function caView(ca: CaRow) {
  return {
    id: ca.id,
    kind: ca.kind,
    parentId: ca.parent_id,
    name: ca.name,
    subject: ca.subject,
    serial: ca.serial,
    keyAlgorithm: ca.key_algorithm,
    notBefore: ca.not_before,
    notAfter: ca.not_after,
    fingerprint: ca.fingerprint,
    certificatePem: ca.cert_pem,
    nameConstraints: ca.name_constraints ? (JSON.parse(ca.name_constraints) as pki.NameConstraintSpec) : null,
    crlNumber: ca.crl_number,
    crlNextUpdate: ca.crl_next_update,
    revokedAt: ca.revoked_at,
    revocationReason: ca.revocation_reason,
    status: certificateStatus(ca),
    createdAt: ca.created_at,
  };
}

export function certificateView(row: CertificateRow) {
  return {
    id: row.id,
    caId: row.ca_id,
    serial: row.serial,
    commonName: row.common_name,
    sans: sansOf(row),
    profile: row.profile,
    keyAlgorithm: row.key_algorithm,
    notBefore: row.not_before,
    notAfter: row.not_after,
    fingerprint: row.fingerprint,
    certificatePem: row.cert_pem,
    tags: JSON.parse(row.tags) as string[],
    notes: row.notes,
    revokedAt: row.revoked_at,
    revocationReason: row.revocation_reason,
    status: certificateStatus(row),
    createdAt: row.created_at,
  };
}
