/** Browser-side CA operations that need the root key (which never leaves the browser). */
import * as pki from "../../shared/pki";
import { api, type Ca } from "./api";

const YEAR_MS = 365 * 86_400_000;

/** Root CRLs are signed offline, so they're long-lived: a year, or until the root expires. */
export function rootCrlHours(rootNotAfter: number): number {
  return Math.max(1, Math.floor((Math.min(Date.now() + YEAR_MS, rootNotAfter) - Date.now()) / 3_600_000));
}

/** Signs a new root CRL listing `revoked` intermediates (plus those already revoked) and uploads it. */
export async function publishRootCrl(root: Ca, children: Ca[], rootKey: CryptoKey, revokeNow: Ca[] = [], reason = 1) {
  const cert = new pki.x509.X509Certificate(root.certificatePem);
  const entries = [
    ...children
      .filter((ch) => ch.revokedAt)
      .map((ch) => ({ serialNumber: ch.serial, revokedAt: new Date(ch.revokedAt!), reason: ch.revocationReason ?? undefined })),
    ...revokeNow.map((ch) => ({ serialNumber: ch.serial, revokedAt: new Date(), reason })),
  ];
  const crl = await pki.createCrl({
    issuer: cert,
    issuerKey: rootKey,
    crlNumber: root.crlNumber + 1,
    validityHours: rootCrlHours(root.notAfter),
    entries,
  });
  return api<{ ca: Ca; revoked: string[] }>(`/cas/${root.id}/crl`, { method: "PUT", json: { crlPem: pki.crlToPem(crl) } });
}

/** Imports a root key PEM and checks that it belongs to `root`. */
export async function unlockRootKey(root: Ca, pem: string): Promise<CryptoKey> {
  const { key } = await pki.importPrivateKeyAuto(pem);
  if (!(await pki.keyMatchesCertificate(key, new pki.x509.X509Certificate(root.certificatePem)))) {
    throw new Error("This key doesn't belong to this root CA");
  }
  return key;
}
