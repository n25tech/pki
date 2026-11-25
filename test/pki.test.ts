/**
 * Runs inside workerd, so this also checks that @peculiar/x509 and the
 * WebCrypto algorithms we rely on work in the Workers runtime.
 */
import { describe, expect, it } from "vitest";
import * as pki from "../src/shared/pki";

const { x509 } = pki;
const constraints = { dns: ["home.arpa", "lan"], ip: ["192.168.0.0/16", "fd00::/8"] };

async function hierarchy(rootAlg: pki.KeyAlgorithm = "ECDSA-P384", interAlg: pki.KeyAlgorithm = "ECDSA-P256") {
  const root = await pki.createRootCa({
    subject: { commonName: "Test Root", organization: "Lab" },
    keyAlgorithm: rootAlg,
    validityDays: 3650,
    nameConstraints: constraints,
  });
  const inter = await pki.createIntermediateCa({
    issuer: root.certificate,
    issuerKey: root.keys.privateKey,
    subject: { commonName: "Test Intermediate" },
    keyAlgorithm: interAlg,
    validityDays: 1825,
    crlUrl: "http://pki-crl.n25tech.com/test.crl",
    issuerCertUrl: "http://pki-crl.n25tech.com/test-root.crt",
  });
  return { root, inter };
}

async function leaf(inter: Awaited<ReturnType<typeof hierarchy>>["inter"], sans: pki.SubjectAltNames, alg: pki.KeyAlgorithm = "ECDSA-P256") {
  const keys = await pki.generateKeyPair(alg);
  return pki.issueLeaf({
    issuer: inter.certificate,
    issuerKey: inter.keys.privateKey,
    constraints,
    publicKey: keys.publicKey,
    subject: { commonName: sans.dns[0] ?? sans.ip[0] },
    sans,
    profile: "server",
    validityDays: 90,
    crlUrl: "http://pki-crl.n25tech.com/test.crl",
  });
}

describe("name constraints validation", () => {
  it("accepts private suffixes and CIDRs", () => {
    expect(pki.validateNameConstraints({ dns: [".Home.Arpa.", "lan"], ip: ["10.0.0.0/8"] })).toEqual({
      dns: ["home.arpa", "lan"],
      ip: ["10.0.0.0/8"],
    });
  });

  it.each([
    [{ dns: [], ip: [] }, /at least one/],
    [{ dns: ["com"], ip: [] }, /top-level domain/],
    [{ dns: ["bad_label.lan"], ip: [] }, /Invalid DNS suffix/],
    [{ dns: [], ip: ["0.0.0.0/0"] }, /too broad/],
    [{ dns: [], ip: ["192.168.1.1"] }, /Invalid IP range/],
  ])("rejects %j", (spec, error) => {
    expect(() => pki.validateNameConstraints(spec)).toThrow(error);
  });
});

describe("CA hierarchy", () => {
  it("creates a constrained root and an intermediate with the right extensions", async () => {
    const { root, inter } = await hierarchy();
    expect(await root.certificate.isSelfSigned()).toBe(true);
    expect(pki.readNameConstraints(root.certificate)).toEqual(constraints);

    const rootBc = root.certificate.getExtension(x509.BasicConstraintsExtension)!;
    expect(rootBc.ca).toBe(true);
    expect(rootBc.pathLength).toBe(1);

    const interBc = inter.certificate.getExtension(x509.BasicConstraintsExtension)!;
    expect(interBc.ca).toBe(true);
    expect(interBc.pathLength).toBe(0);
    expect(await inter.certificate.verify({ publicKey: root.certificate.publicKey, signatureOnly: true })).toBe(true);
    expect(inter.certificate.notAfter.getTime()).toBeLessThanOrEqual(root.certificate.notAfter.getTime());
  });

  it("supports RSA issuers", async () => {
    const { inter } = await hierarchy("RSA-2048", "RSA-2048");
    const { certificate } = await leaf(inter, { dns: ["nas.lan"], ip: [] }, "RSA-2048");
    expect(await certificate.verify({ publicKey: inter.certificate.publicKey, signatureOnly: true })).toBe(true);
  });

  it("round-trips a private key through PKCS#8", async () => {
    const { inter } = await hierarchy();
    const pkcs8 = await pki.exportPrivateKey(inter.keys.privateKey);
    const key = await pki.importPrivateKey(pkcs8, "ECDSA-P256");
    expect(pki.privateKeyToPem(pkcs8)).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(key.type).toBe("private");
  });
});

describe("leaf issuance", () => {
  it("issues a server certificate with SANs, EKU and CRL distribution point", async () => {
    const { inter } = await hierarchy();
    const { certificate } = await leaf(inter, { dns: ["nas.home.arpa", "*.k8s.lan"], ip: ["192.168.1.10", "fd00::10"] });

    expect(await certificate.verify({ publicKey: inter.certificate.publicKey, signatureOnly: true })).toBe(true);
    expect(certificate.getExtension(x509.BasicConstraintsExtension)!.ca).toBe(false);
    expect(certificate.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual([x509.ExtendedKeyUsage.serverAuth]);
    const sans = certificate.getExtension(x509.SubjectAlternativeNameExtension)!.names.toJSON();
    expect(sans).toEqual([
      { type: "dns", value: "nas.home.arpa" },
      { type: "dns", value: "*.k8s.lan" },
      { type: "ip", value: "192.168.1.10" },
      { type: "ip", value: "fd00::10" },
    ]);
    const dp = certificate.getExtension(x509.CRLDistributionPointsExtension)!;
    expect(JSON.stringify(dp.distributionPoints)).toContain("pki-crl.n25tech.com/test.crl");
  });

  it.each([
    [{ dns: ["google.com"], ip: [] }, /name constraints: google.com/],
    [{ dns: ["home.arpa.evil.com"], ip: [] }, /name constraints/],
    [{ dns: ["evilhome.arpa"], ip: [] }, /name constraints/],
    [{ dns: [], ip: ["8.8.8.8"] }, /name constraints: 8.8.8.8/],
    [{ dns: [], ip: ["not-an-ip"] }, /Invalid IP/],
    [{ dns: [], ip: [] }, /At least one/],
  ])("refuses %j", async (sans, error) => {
    const { inter } = await hierarchy();
    await expect(leaf(inter, sans)).rejects.toThrow(error);
  });

  it("enforces the maximum validity", async () => {
    const { inter } = await hierarchy();
    const keys = await pki.generateKeyPair("ECDSA-P256");
    await expect(
      pki.issueLeaf({
        issuer: inter.certificate,
        issuerKey: inter.keys.privateKey,
        constraints,
        publicKey: keys.publicKey,
        subject: { commonName: "nas.lan" },
        sans: { dns: ["nas.lan"], ip: [] },
        profile: "server",
        validityDays: pki.MAX_LEAF_VALIDITY_DAYS + 1,
      }),
    ).rejects.toThrow(pki.PolicyError);
  });

  it("issues from a CSR after checking its signature", async () => {
    const { inter } = await hierarchy();
    const keys = await pki.generateKeyPair("ECDSA-P256");
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=printer.lan",
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    const parsed = await pki.parseCsr(csr.toString("pem"));
    const { certificate } = await pki.issueLeaf({
      issuer: inter.certificate,
      issuerKey: inter.keys.privateKey,
      constraints,
      publicKey: parsed.publicKey,
      subject: { commonName: "printer.lan" },
      sans: { dns: ["printer.lan"], ip: [] },
      profile: "server",
      validityDays: 30,
    });
    expect(await certificate.publicKey.getThumbprint()).toEqual(await parsed.publicKey.getThumbprint());
  });
});

describe("revocation and lookup", () => {
  it("creates a signed CRL listing revoked serials", async () => {
    const { inter } = await hierarchy();
    const { certificate } = await leaf(inter, { dns: ["nas.lan"], ip: [] });
    const crl = await pki.createCrl({
      issuer: inter.certificate,
      issuerKey: inter.keys.privateKey,
      crlNumber: 7,
      entries: [{ serialNumber: certificate.serialNumber, revokedAt: new Date(), reason: x509.X509CrlReason.keyCompromise }],
    });
    expect(await crl.verify({ publicKey: inter.certificate.publicKey })).toBe(true);
    expect(crl.entries.map((e) => e.serialNumber)).toEqual([certificate.serialNumber]);
    expect(crl.entries[0].reason).toBe(x509.X509CrlReason.keyCompromise);
    expect(pki.crlToPem(crl)).toMatch(/^-----BEGIN X509 CRL-----/);
  });

  it("finds the issuing chain for a certificate and rejects unrelated CAs", async () => {
    const { root, inter } = await hierarchy();
    const other = await hierarchy();
    const { certificate } = await leaf(inter, { dns: ["nas.lan"], ip: [] });

    const found = await pki.findIssuingChain(certificate, [root.certificate, inter.certificate]);
    expect(found.status).toBe("issued");
    if (found.status === "issued") {
      expect(found.chain.map((c) => c.subject)).toEqual(["CN=nas.lan", "CN=Test Intermediate", "CN=Test Root, O=Lab"]);
    }
    // Same subject names, different keys: must not match.
    expect((await pki.findIssuingChain(certificate, [other.root.certificate, other.inter.certificate])).status).toBe("unknown");
  });

  it("generates unique positive serials", () => {
    const serials = new Set(Array.from({ length: 200 }, () => pki.randomSerial()));
    expect(serials.size).toBe(200);
    for (const s of serials) expect(parseInt(s[0], 16)).toBeLessThan(8);
  });
});
