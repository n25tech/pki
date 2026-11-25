/**
 * Certificate authority primitives shared by the browser and the Worker.
 *
 * Everything here uses WebCrypto (`globalThis.crypto`) through @peculiar/x509,
 * so the same code runs in browsers (key generation, root self-signing, CSRs)
 * and in the Workers runtime (signing intermediates and leaves, CRLs, lookup).
 */
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import {
  CRLNumber,
  GeneralName,
  GeneralSubtree,
  GeneralSubtrees,
  NameConstraints,
  id_ce_cRLNumber,
  id_ce_nameConstraints,
} from "@peculiar/asn1-x509";
import { PUBLIC_SUFFIXES, PUBLIC_SUFFIX_EXCEPTIONS, PUBLIC_SUFFIX_WILDCARDS } from "./publicSuffixes";

x509.cryptoProvider.set(crypto);

// Structural WebCrypto parameter types. The DOM lib and the Workers runtime
// types name these differently, so the shared code defines its own.
type SignAlgorithm = { name: string; hash?: string };
type KeyGenAlgorithm = {
  name: string;
  namedCurve?: string;
  modulusLength?: number;
  publicExponent?: Uint8Array;
  hash?: string;
};

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

export const KEY_ALGORITHMS = ["ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072", "RSA-4096"] as const;
export type KeyAlgorithm = (typeof KEY_ALGORITHMS)[number];

interface AlgorithmSpec {
  generate: KeyGenAlgorithm;
  sign: SignAlgorithm;
}

const ALGORITHMS: Record<KeyAlgorithm, AlgorithmSpec> = {
  "ECDSA-P256": {
    generate: { name: "ECDSA", namedCurve: "P-256" },
    sign: { name: "ECDSA", hash: "SHA-256" },
  },
  "ECDSA-P384": {
    generate: { name: "ECDSA", namedCurve: "P-384" },
    sign: { name: "ECDSA", hash: "SHA-384" },
  },
  ...Object.fromEntries(
    ([2048, 3072, 4096] as const).map((bits) => [
      `RSA-${bits}`,
      {
        generate: {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: bits,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        sign: { name: "RSASSA-PKCS1-v1_5" },
      },
    ]),
  ),
} as Record<KeyAlgorithm, AlgorithmSpec>;

/** Generates an extractable key pair, so the caller can export or wrap the private key. */
export async function generateKeyPair(alg: KeyAlgorithm): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(ALGORITHMS[alg].generate, true, ["sign", "verify"])) as CryptoKeyPair;
}

/** The signature algorithm to use when `key` signs something. */
export function signingAlgorithmFor(key: CryptoKey): SignAlgorithm {
  const alg = key.algorithm as { name: string; namedCurve?: string };
  if (alg.name === "ECDSA") {
    return { name: "ECDSA", hash: alg.namedCurve === "P-384" ? "SHA-384" : "SHA-256" };
  }
  if (alg.name === "RSASSA-PKCS1-v1_5") return { name: "RSASSA-PKCS1-v1_5" };
  throw new Error(`Unsupported signing key algorithm: ${alg.name}`);
}

/** Re-imports a PKCS#8 private key produced by `exportPrivateKey`. */
export async function importPrivateKey(pkcs8: ArrayBuffer, alg: KeyAlgorithm): Promise<CryptoKey> {
  const gen = ALGORITHMS[alg].generate;
  const params = gen.name === "ECDSA" ? gen : { name: gen.name, hash: gen.hash };
  return crypto.subtle.importKey("pkcs8", pkcs8, params, true, ["sign"]);
}

export async function exportPrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
  return (await crypto.subtle.exportKey("pkcs8", key)) as ArrayBuffer;
}

export function privateKeyToPem(pkcs8: ArrayBuffer): string {
  return x509.PemConverter.encode(pkcs8, "PRIVATE KEY");
}

// ---------------------------------------------------------------------------
// Name constraints
// ---------------------------------------------------------------------------

/**
 * Names the Public Suffix List includes but that are reserved for private
 * networks, so nobody can register public domains under them.
 * home.arpa: RFC 8375 (residential home networks).
 */
const RESERVED_PRIVATE_NAMES: ReadonlySet<string> = new Set(["home.arpa"]);

/**
 * True when `name` is a public suffix: a name under which anyone can register
 * their own domain. That covers IANA's top-level domains ("com", "uk") and the
 * Public Suffix List, both ICANN entries ("co.uk", "com.au") and private ones
 * ("github.io", "workers.dev"). A root may not be constrained to a public
 * suffix, because it could then sign certificates for every site under it.
 * Private names that aren't public suffixes ("lan", "kubernetes", "svc",
 * "cluster.local", "n25tech.com") are fine.
 */
export function isPublicSuffix(name: string): boolean {
  const n = normalizeDnsSuffix(name);
  if (RESERVED_PRIVATE_NAMES.has(n)) return false;
  if (PUBLIC_SUFFIXES.has(n)) return true;
  // "*.ck" makes every "<label>.ck" a public suffix, except listed exceptions like "www.ck".
  const dot = n.indexOf(".");
  return dot > 0 && PUBLIC_SUFFIX_WILDCARDS.has(n.slice(dot + 1)) && !PUBLIC_SUFFIX_EXCEPTIONS.has(n);
}

export const DEFAULT_PERMITTED_DNS = ["home.arpa", "lan", "internal"];
export const DEFAULT_PERMITTED_IP = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"];

export interface NameConstraintSpec {
  /** Permitted DNS suffixes, e.g. "home.arpa" (matches the name and all subdomains). */
  dns: string[];
  /** Permitted IP ranges in CIDR notation. */
  ip: string[];
}

const DNS_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

export function normalizeDnsSuffix(input: string): string {
  return input.trim().toLowerCase().replace(/^\.+/, "").replace(/\.+$/, "");
}

/** Throws if the constraints are missing or too broad. Returns a normalized copy. */
export function validateNameConstraints(spec: NameConstraintSpec): NameConstraintSpec {
  const dns = [...new Set(spec.dns.map(normalizeDnsSuffix))];
  const ip = [...new Set(spec.ip.map((s) => s.trim()))];
  if (dns.length === 0 && ip.length === 0) {
    throw new Error("A root CA must be restricted to at least one DNS suffix or IP range");
  }
  for (const suffix of dns) {
    const labels = suffix.split(".");
    if (!suffix || !labels.every((l) => DNS_LABEL.test(l))) {
      throw new Error(`Invalid DNS suffix: "${suffix}"`);
    }
    if (isPublicSuffix(suffix)) {
      throw new Error(`"${suffix}" is a public suffix (anyone can register names under it); use a domain under it (e.g. "example.${suffix}") instead`);
    }
  }
  for (const cidr of ip) {
    const parsed = parseCidr(cidr);
    if (!parsed) throw new Error(`Invalid IP range (use CIDR, e.g. 192.168.0.0/16): "${cidr}"`);
    if (parsed.prefix < 8) {
      throw new Error(`IP range "${cidr}" is too broad`);
    }
  }
  return { dns, ip };
}

function nameConstraintsExtension(spec: NameConstraintSpec): x509.Extension {
  const subtrees = [
    ...spec.dns.map((d) => new GeneralSubtree({ base: new GeneralName({ dNSName: d }) })),
    ...spec.ip.map((c) => new GeneralSubtree({ base: new GeneralName({ iPAddress: c }) })),
  ];
  const value = AsnConvert.serialize(new NameConstraints({ permittedSubtrees: new GeneralSubtrees(subtrees) }));
  return new x509.Extension(id_ce_nameConstraints, true, value);
}

/** Reads the permitted subtrees back out of a CA certificate (empty if unconstrained). */
export function readNameConstraints(cert: x509.X509Certificate): NameConstraintSpec | null {
  const ext = cert.getExtension(id_ce_nameConstraints);
  if (!ext) return null;
  const nc = AsnConvert.parse(ext.value, NameConstraints);
  const spec: NameConstraintSpec = { dns: [], ip: [] };
  for (const subtree of nc.permittedSubtrees ?? []) {
    if (subtree.base.dNSName) spec.dns.push(subtree.base.dNSName);
    if (subtree.base.iPAddress) spec.ip.push(subtree.base.iPAddress);
  }
  return spec;
}

// ---------------------------------------------------------------------------
// IP helpers (used for constraint checks)
// ---------------------------------------------------------------------------

function parseIp(ip: string): Uint8Array | null {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    const parts = ip.split(".").map(Number);
    return parts.every((p) => p >= 0 && p <= 255) ? new Uint8Array(parts) : null;
  }
  if (!/^[0-9a-f:]+$/i.test(ip) || ip.split("::").length > 2) return null;
  const [left, right = ""] = ip.split("::");
  const l = left ? left.split(":") : [];
  const r = ip.includes("::") && right ? right.split(":") : [];
  const missing = 8 - l.length - r.length;
  if ((!ip.includes("::") && missing !== 0) || missing < 0) return null;
  const groups = [...l, ...Array(ip.includes("::") ? missing : 0).fill("0"), ...r];
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    const n = parseInt(g, 16);
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 0xff;
  });
  return out;
}

function parseCidr(cidr: string): { bytes: Uint8Array; prefix: number } | null {
  const [addr, prefixStr, extra] = cidr.split("/");
  if (extra !== undefined || prefixStr === undefined || !/^\d{1,3}$/.test(prefixStr)) return null;
  const bytes = parseIp(addr);
  const prefix = Number(prefixStr);
  if (!bytes || prefix > bytes.length * 8) return null;
  return { bytes, prefix };
}

function ipInCidr(ip: string, cidr: string): boolean {
  const addr = parseIp(ip);
  const range = parseCidr(cidr);
  if (!addr || !range || addr.length !== range.bytes.length) return false;
  for (let bit = 0; bit < range.prefix; bit++) {
    const byte = bit >> 3;
    const mask = 0x80 >> (bit & 7);
    if ((addr[byte] & mask) !== (range.bytes[byte] & mask)) return false;
  }
  return true;
}

export interface SubjectAltNames {
  dns: string[];
  ip: string[];
}

/**
 * Returns the SANs that fall outside the constraints. An empty result means the
 * names are allowed. This mirrors RFC 5280 semantics for permitted subtrees:
 * a DNS constraint "home.arpa" permits "home.arpa" and "*.home.arpa".
 */
export function namesOutsideConstraints(names: SubjectAltNames, spec: NameConstraintSpec): string[] {
  const bad: string[] = [];
  for (const raw of names.dns) {
    const name = raw.toLowerCase().replace(/\.$/, "");
    const ok = spec.dns.some((suffix) => name === suffix || name.endsWith(`.${suffix}`));
    if (!ok) bad.push(raw);
  }
  for (const ip of names.ip) {
    if (!spec.ip.some((cidr) => ipInCidr(ip, cidr))) bad.push(ip);
  }
  return bad;
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

export interface DistinguishedName {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
}

function dnToString(dn: DistinguishedName): string {
  const escape = (v: string) => v.replace(/([,+"\\<>;=])/g, "\\$1");
  const parts = [`CN=${escape(dn.commonName)}`];
  if (dn.organizationalUnit) parts.push(`OU=${escape(dn.organizationalUnit)}`);
  if (dn.organization) parts.push(`O=${escape(dn.organization)}`);
  if (dn.country) parts.push(`C=${escape(dn.country)}`);
  return parts.join(", ");
}

/** A random, positive, non-zero 128-bit serial number as hex. */
export function randomSerial(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[0] &= 0x7f;
  bytes[0] |= 0x01;
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * 86_400_000);
}

/** Backdate notBefore slightly to tolerate clock skew on clients. */
function notBeforeNow(): Date {
  return new Date(Date.now() - 5 * 60_000);
}

export interface CreateRootParams {
  subject: DistinguishedName;
  keyAlgorithm: KeyAlgorithm;
  validityDays: number;
  nameConstraints: NameConstraintSpec;
}

/**
 * Creates a self-signed root CA. Path length 1 allows exactly one intermediate tier.
 */
export async function createRootCa(params: CreateRootParams) {
  const constraints = validateNameConstraints(params.nameConstraints);
  const keys = await generateKeyPair(params.keyAlgorithm);
  const notBefore = notBeforeNow();
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerial(),
    name: dnToString(params.subject),
    notBefore,
    notAfter: addDays(notBefore, params.validityDays),
    keys,
    signingAlgorithm: ALGORITHMS[params.keyAlgorithm].sign,
    extensions: [
      new x509.BasicConstraintsExtension(true, 1, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      nameConstraintsExtension(constraints),
    ],
  });
  return { certificate, keys };
}

export interface CreateIntermediateParams {
  issuer: x509.X509Certificate;
  issuerKey: CryptoKey;
  subject: DistinguishedName;
  keyAlgorithm: KeyAlgorithm;
  validityDays: number;
  /** URL of the issuer's CRL, embedded as the CRL distribution point. */
  crlUrl?: string;
  /** URL where the issuer certificate can be downloaded (AIA caIssuers). */
  issuerCertUrl?: string;
}

/** Creates an intermediate CA signed by a root. Path length 0: it may only issue leaf certificates. */
export async function createIntermediateCa(params: CreateIntermediateParams) {
  const keys = await generateKeyPair(params.keyAlgorithm);
  const certificate = await signIntermediateCa({ ...params, publicKey: keys.publicKey });
  return { certificate, keys };
}

/**
 * Signs an intermediate CA certificate for an existing public key (e.g. from a
 * CSR). Path length 0: it may only issue leaf certificates.
 */
export async function signIntermediateCa(
  params: Omit<CreateIntermediateParams, "keyAlgorithm"> & { publicKey: CryptoKey | x509.PublicKey },
): Promise<x509.X509Certificate> {
  const notBefore = notBeforeNow();
  const notAfter = minDate(addDays(notBefore, params.validityDays), params.issuer.notAfter);
  return x509.X509CertificateGenerator.create({
    serialNumber: randomSerial(),
    subject: dnToString(params.subject),
    issuer: params.issuer.subjectName,
    notBefore,
    notAfter,
    publicKey: params.publicKey,
    signingKey: params.issuerKey,
    signingAlgorithm: signingAlgorithmFor(params.issuerKey),
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(params.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(params.issuer.publicKey),
      ...distributionExtensions(params.crlUrl, params.issuerCertUrl),
    ],
  });
}

export type LeafProfile = "server" | "client";

export const MAX_LEAF_VALIDITY_DAYS = 398;

export interface IssueLeafParams {
  issuer: x509.X509Certificate;
  issuerKey: CryptoKey;
  /** The root's name constraints; issuance is refused for names outside them. */
  constraints: NameConstraintSpec;
  publicKey: CryptoKey | x509.PublicKey;
  subject: DistinguishedName;
  sans: SubjectAltNames;
  profile: LeafProfile;
  validityDays: number;
  crlUrl?: string;
  issuerCertUrl?: string;
}

export class PolicyError extends Error {}

/** Issues an end-entity certificate after enforcing the CA's name constraints. */
export async function issueLeaf(params: IssueLeafParams) {
  const sans = {
    dns: params.sans.dns.map((d) => d.trim().toLowerCase()).filter(Boolean),
    ip: params.sans.ip.map((i) => i.trim()).filter(Boolean),
  };
  if (sans.dns.length + sans.ip.length === 0) {
    throw new PolicyError("At least one DNS name or IP address is required");
  }
  const badIp = sans.ip.filter((ip) => !parseIp(ip));
  if (badIp.length) throw new PolicyError(`Invalid IP address: ${badIp.join(", ")}`);
  const outside = namesOutsideConstraints(sans, params.constraints);
  if (outside.length) {
    throw new PolicyError(`Not permitted by this CA's name constraints: ${outside.join(", ")}`);
  }
  if (params.validityDays < 1 || params.validityDays > MAX_LEAF_VALIDITY_DAYS) {
    throw new PolicyError(`Validity must be between 1 and ${MAX_LEAF_VALIDITY_DAYS} days`);
  }

  const publicKey = params.publicKey;
  const isRsa = publicKey.algorithm.name.startsWith("RSA");
  let usages = x509.KeyUsageFlags.digitalSignature;
  if (isRsa && params.profile === "server") usages |= x509.KeyUsageFlags.keyEncipherment;

  const notBefore = notBeforeNow();
  const notAfter = minDate(addDays(notBefore, params.validityDays), params.issuer.notAfter);
  const certificate = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerial(),
    subject: dnToString(params.subject),
    issuer: params.issuer.subjectName,
    notBefore,
    notAfter,
    publicKey,
    signingKey: params.issuerKey,
    signingAlgorithm: signingAlgorithmFor(params.issuerKey),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(usages, true),
      new x509.ExtendedKeyUsageExtension(
        [params.profile === "server" ? x509.ExtendedKeyUsage.serverAuth : x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      new x509.SubjectAlternativeNameExtension(
        [
          ...sans.dns.map((value) => ({ type: "dns" as const, value })),
          ...sans.ip.map((value) => ({ type: "ip" as const, value })),
        ],
        false,
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(params.issuer.publicKey),
      ...distributionExtensions(params.crlUrl, params.issuerCertUrl),
    ],
  });
  return { certificate };
}

function distributionExtensions(crlUrl?: string, issuerCertUrl?: string): x509.Extension[] {
  const exts: x509.Extension[] = [];
  if (crlUrl) exts.push(new x509.CRLDistributionPointsExtension([crlUrl]));
  if (issuerCertUrl) exts.push(new x509.AuthorityInfoAccessExtension({ caIssuers: [issuerCertUrl] }));
  return exts;
}

function minDate(a: Date, b: Date): Date {
  return a.getTime() <= b.getTime() ? a : b;
}

// ---------------------------------------------------------------------------
// CSRs
// ---------------------------------------------------------------------------

/** Parses a PEM/DER CSR and checks its self-signature (proof of key possession). */
export async function parseCsr(csr: string | ArrayBuffer) {
  const req = new x509.Pkcs10CertificateRequest(csr);
  if (!(await req.verify())) throw new PolicyError("CSR signature is invalid");
  return req;
}

/** Creates a CSR in the browser for a key that never leaves it. */
export async function createCsr(keys: CryptoKeyPair, commonName: string, sans: SubjectAltNames) {
  const extensions: x509.Extension[] = [];
  const names = [
    ...sans.dns.map((value) => ({ type: "dns" as const, value })),
    ...sans.ip.map((value) => ({ type: "ip" as const, value })),
  ];
  if (names.length) extensions.push(new x509.SubjectAlternativeNameExtension(names));
  return x509.Pkcs10CertificateRequestGenerator.create({
    name: dnToString({ commonName }),
    keys,
    signingAlgorithm: signingAlgorithmFor(keys.privateKey),
    extensions,
  });
}

/** The SANs requested in a CSR, if it has a subjectAltName extension. */
export function csrSubjectAltNames(csr: x509.Pkcs10CertificateRequest): SubjectAltNames {
  const raw = csr.getExtension("2.5.29.17");
  const ext = raw ? new x509.SubjectAlternativeNameExtension(raw.rawData) : null;
  const out: SubjectAltNames = { dns: [], ip: [] };
  for (const n of ext?.names.toJSON() ?? []) {
    if (n.type === "dns") out.dns.push(n.value);
    if (n.type === "ip") out.ip.push(n.value);
  }
  return out;
}

export function csrCommonName(csr: x509.Pkcs10CertificateRequest): string | null {
  return csr.subjectName.getField("CN")[0] ?? null;
}

// ---------------------------------------------------------------------------
// Keys and certificates: inspection
// ---------------------------------------------------------------------------

/** Identifies the key algorithm of a certificate or CSR public key. */
export function describePublicKey(publicKey: x509.PublicKey): KeyAlgorithm | null {
  const alg = publicKey.algorithm as { name: string; namedCurve?: string; modulusLength?: number };
  if (alg.name === "ECDSA" || alg.name === "ECDH") {
    if (alg.namedCurve === "P-256") return "ECDSA-P256";
    if (alg.namedCurve === "P-384") return "ECDSA-P384";
    return null;
  }
  if (alg.name.startsWith("RSA")) {
    const bits = alg.modulusLength;
    if (bits === 2048 || bits === 3072 || bits === 4096) return `RSA-${bits}` as KeyAlgorithm;
  }
  return null;
}

/** Imports a PKCS#8 key (DER or PEM) without knowing its algorithm in advance. */
export async function importPrivateKeyAuto(input: ArrayBuffer | string): Promise<{ key: CryptoKey; algorithm: KeyAlgorithm }> {
  const der = typeof input === "string" ? x509.PemConverter.decodeFirst(input) : input;
  for (const algorithm of ["ECDSA-P256", "ECDSA-P384", "RSA-2048"] as const) {
    try {
      const key = await importPrivateKey(der, algorithm);
      const a = key.algorithm as { name: string; modulusLength?: number };
      const resolved = a.name.startsWith("RSA") ? (`RSA-${a.modulusLength}` as KeyAlgorithm) : algorithm;
      if (!KEY_ALGORITHMS.includes(resolved)) throw new Error("Unsupported RSA key size");
      return { key, algorithm: resolved };
    } catch {
      // try the next algorithm
    }
  }
  throw new Error("Not a supported private key (expected an unencrypted PKCS#8 ECDSA P-256/P-384 or RSA key)");
}

/** True when `privateKey` belongs to the public key of `cert` (a certificate or CSR), by a sign/verify round trip. */
export async function keyMatchesCertificate(privateKey: CryptoKey, cert: { publicKey: x509.PublicKey }): Promise<boolean> {
  try {
    const data = crypto.getRandomValues(new Uint8Array(32));
    const alg = signingAlgorithmFor(privateKey);
    const signature = await crypto.subtle.sign(alg, privateKey, data);
    const publicKey = await cert.publicKey.export(
      { ...(privateKey.algorithm as object), ...alg } as Parameters<typeof cert.publicKey.export>[0],
      ["verify"],
    );
    return await crypto.subtle.verify(alg, publicKey, signature, data);
  } catch {
    return false;
  }
}

/** SHA-256 fingerprint of the DER encoding, lower-case hex. */
export async function fingerprint(item: { rawData: ArrayBuffer }): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", item.rawData);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Parses one PEM or DER certificate, with a friendly error. */
export function parseCertificate(input: string | ArrayBuffer): x509.X509Certificate {
  try {
    return new x509.X509Certificate(input);
  } catch {
    throw new PolicyError("Not a valid X.509 certificate");
  }
}

export function parseCrl(input: string | ArrayBuffer): x509.X509Crl {
  try {
    const data = typeof input === "string" ? x509.PemConverter.decodeFirst(input) : input;
    return new x509.X509Crl(data);
  } catch {
    throw new PolicyError("Not a valid CRL");
  }
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

export interface RevokedEntry {
  serialNumber: string;
  revokedAt: Date;
  reason?: x509.X509CrlReason;
}

export interface CreateCrlParams {
  issuer: x509.X509Certificate;
  issuerKey: CryptoKey;
  /** Monotonically increasing per issuer (RFC 5280 §5.2.3). */
  crlNumber: number;
  entries: RevokedEntry[];
  /** How long clients may cache this CRL. */
  validityHours?: number;
}

/** The CRL Number extension value, or null if absent. */
export function crlNumberOf(crl: x509.X509Crl): number | null {
  const ext = crl.extensions.find((e) => e.type === id_ce_cRLNumber);
  return ext ? AsnConvert.parse(ext.value, CRLNumber).value : null;
}

export async function createCrl(params: CreateCrlParams): Promise<x509.X509Crl> {
  const thisUpdate = new Date();
  return x509.X509CrlGenerator.create({
    issuer: params.issuer.subjectName,
    thisUpdate,
    nextUpdate: new Date(thisUpdate.getTime() + (params.validityHours ?? 24 * 7) * 3_600_000),
    signingKey: params.issuerKey,
    signingAlgorithm: signingAlgorithmFor(params.issuerKey),
    extensions: [
      await x509.AuthorityKeyIdentifierExtension.create(params.issuer.publicKey),
      new x509.Extension(id_ce_cRLNumber, false, AsnConvert.serialize(new CRLNumber(params.crlNumber))),
    ],
    entries: params.entries.map((e) => ({
      serialNumber: e.serialNumber,
      revocationDate: e.revokedAt,
      reason: e.reason,
    })),
  });
}

/**
 * PEM-encodes a CRL with the standard "X509 CRL" label. (The library's own
 * toString("pem") writes "CRL", which OpenSSL and most tools reject.)
 * CRL distribution points should serve the DER bytes (`crl.rawData`) instead.
 */
export function crlToPem(crl: x509.X509Crl): string {
  return x509.PemConverter.encode(crl.rawData, "X509 CRL");
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

export type LookupResult =
  | { status: "issued"; chain: x509.X509Certificate[] }
  | { status: "unknown" };

/**
 * Checks whether `cert` chains, with valid signatures at every link, to one of
 * the given CA certificates. Does not check revocation or expiry; callers add those.
 */
export async function findIssuingChain(
  cert: x509.X509Certificate,
  caCertificates: x509.X509Certificate[],
): Promise<LookupResult> {
  const builder = new x509.X509ChainBuilder({ certificates: caCertificates });
  let chain: x509.X509Certificate[];
  try {
    chain = [...(await builder.build(cert))];
  } catch {
    return { status: "unknown" };
  }
  if (chain.length < 2) return { status: "unknown" };
  for (let i = 0; i < chain.length - 1; i++) {
    if (!(await chain[i].verify({ publicKey: chain[i + 1].publicKey, signatureOnly: true }))) {
      return { status: "unknown" };
    }
  }
  const top = chain[chain.length - 1];
  if (!(await top.isSelfSigned())) return { status: "unknown" };
  return { status: "issued", chain };
}

export { x509 };
