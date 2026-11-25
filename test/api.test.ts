import { describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import * as pki from "../src/shared/pki";
import { Client, constraints, createIntermediate, createRoot, csrFor, nextTotp, signedInClient, uniqueEmail } from "./helpers";

const { x509 } = pki;

describe("accounts and sessions", () => {
  it("registers, signs out, and signs back in with password + TOTP", async () => {
    const { client, email, password, secret } = await signedInClient();
    expect((await client.json("/api/auth/me")).body).toMatchObject({ user: { email, mfaEnabled: true }, stage: "full" });

    await client.json("/api/auth/logout", { json: {} });
    expect((await client.json("/api/auth/me")).body).toEqual({ user: null });

    const bad = await client.json("/api/auth/login", { json: { email, password: "wrong password!!" } });
    expect(bad.status).toBe(401);

    const login = await client.json("/api/auth/login", { json: { email, password } });
    expect(login.body).toEqual({ mfaRequired: true });
    expect((await client.json("/api/auth/me")).body.stage).toBe("mfa");
    expect((await client.json("/api/cas")).status).toBe(401);

    expect((await client.json("/api/auth/mfa", { json: { code: "000000" } })).status).toBe(401);
    const code = await nextTotp(secret);
    expect((await client.json("/api/auth/mfa", { json: { code } })).status).toBe(200);
    expect((await client.json("/api/cas")).status).toBe(200);

    // The same code can't be used twice.
    await client.json("/api/auth/logout", { json: {} });
    await client.json("/api/auth/login", { json: { email, password } });
    expect((await client.json("/api/auth/mfa", { json: { code } })).status).toBe(401);
  });

  it("accepts each recovery code once", async () => {
    const { client, email, password, recoveryCodes } = await signedInClient();
    expect(recoveryCodes).toHaveLength(10);
    await client.json("/api/auth/logout", { json: {} });
    await client.json("/api/auth/login", { json: { email, password } });
    expect((await client.json("/api/auth/mfa", { json: { recoveryCode: recoveryCodes[0].toUpperCase() } })).status).toBe(200);

    await client.json("/api/auth/logout", { json: {} });
    await client.json("/api/auth/login", { json: { email, password } });
    expect((await client.json("/api/auth/mfa", { json: { recoveryCode: recoveryCodes[0] } })).status).toBe(401);
  });

  it("requires 2FA before any CA work", async () => {
    const client = new Client();
    await client.json("/api/auth/register", { json: { email: uniqueEmail(), password: "long enough password" } });
    expect((await client.json("/api/auth/me")).body.stage).toBe("setup");
    const res = await client.json("/api/cas");
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("mfa_setup_required");
  });

  it("rejects weak passwords, duplicate emails and cross-origin writes", async () => {
    const email = uniqueEmail();
    expect((await new Client().json("/api/auth/register", { json: { email, password: "short" } })).status).toBe(400);
    expect((await new Client().json("/api/auth/register", { json: { email, password: "long enough password" } })).status).toBe(201);
    expect((await new Client().json("/api/auth/register", { json: { email, password: "long enough password" } })).status).toBe(409);
    const evil = await new Client().json("/api/auth/login", {
      json: { email, password: "long enough password" },
      headers: { Origin: "https://evil.example" },
    });
    expect(evil.status).toBe(403);
  });

  it("sets a host-only, secure, HttpOnly session cookie", async () => {
    const client = new Client();
    const res = await client.fetch("/api/auth/register", { json: { email: uniqueEmail(), password: "long enough password" } });
    const cookie = res.headers.getSetCookie().find((c) => c.startsWith("__Host-pki_session="))!;
    expect(cookie).toMatch(/Secure/);
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Lax/);
    expect(cookie).toMatch(/Path=\//);
    expect(cookie).not.toMatch(/Domain=/i);
  });

  it("verifies email and resets passwords with single-use tokens", async () => {
    const email = uniqueEmail();
    const client = new Client();
    await client.json("/api/auth/register", { json: { email, password: "long enough password" } });
    const user = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first<{ id: string }>();

    // Tokens are stored hashed; plant a known one to simulate clicking the emailed link.
    const plant = async (kind: string, token: string) => {
      const { sha256Hex } = await import("../src/worker/lib/util");
      await env.DB.prepare("INSERT INTO tokens (id, user_id, kind, expires_at) VALUES (?, ?, ?, ?)")
        .bind(await sha256Hex(token), user!.id, kind, Date.now() + 60_000)
        .run();
    };
    await plant("verify_email", "verify-token");
    expect((await client.json("/api/auth/verify-email", { json: { token: "verify-token" } })).status).toBe(200);
    expect((await client.json("/api/auth/me")).body.user.emailVerified).toBe(true);
    expect((await client.json("/api/auth/verify-email", { json: { token: "verify-token" } })).status).toBe(400);

    await plant("reset_password", "reset-token");
    const other = new Client();
    expect((await other.json("/api/auth/reset", { json: { token: "reset-token", password: "a brand new password" } })).status).toBe(200);
    // Existing sessions are signed out by a reset.
    expect((await client.json("/api/auth/me")).body.user).toBeNull();
    expect((await other.json("/api/auth/login", { json: { email, password: "a brand new password" } })).status).toBe(200);
  });

  it("answers password-reset requests the same way for unknown emails", async () => {
    const res = await new Client().json("/api/auth/forgot", { json: { email: "nobody@example.com" } });
    expect(res).toEqual({ status: 200, body: { ok: true } });
  });
});

describe("certificate authorities", () => {
  it("registers a root and intermediate, and never stores the root key", async () => {
    const { client } = await signedInClient();
    const root = await createRoot(client);
    expect(root.res.status).toBe(201);
    expect(root.res.body.ca).toMatchObject({ kind: "root", nameConstraints: constraints });

    const inter = await createIntermediate(client, root);
    expect(inter.res.status).toBe(201);
    expect(inter.res.body.ca).toMatchObject({ kind: "intermediate", parentId: root.id, crlNumber: 1 });

    const rows = await env.DB.prepare("SELECT kind, key_enc FROM cas WHERE id IN (?, ?)").bind(root.id, inter.id).all<{ kind: string; key_enc: string | null }>();
    const byKind = Object.fromEntries(rows.results.map((r) => [r.kind, r.key_enc]));
    expect(byKind.root).toBeNull();
    expect(byKind.intermediate).toMatch(/^v1\./);
    // The stored intermediate key is encrypted, not PEM.
    expect(byKind.intermediate).not.toContain("PRIVATE KEY");

    const list = await client.json("/api/cas");
    expect(list.body.cas.map((c: { id: string }) => c.id)).toEqual([root.id, inter.id]);
  });

  it("rejects roots without name constraints, or with overly broad ones", async () => {
    const { client } = await signedInClient();
    const keys = await pki.generateKeyPair("ECDSA-P256");
    const unconstrained = await x509.X509CertificateGenerator.createSelfSigned({
      name: "CN=Unconstrained",
      keys,
      notAfter: new Date(Date.now() + 86400_000),
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.BasicConstraintsExtension(true, 1, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      ],
    });
    const crl = await pki.createCrl({ issuer: unconstrained, issuerKey: keys.privateKey, crlNumber: 1, entries: [] });
    const res = await client.json("/api/cas/roots", {
      json: { certificatePem: unconstrained.toString("pem"), crlPem: pki.crlToPem(crl) },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("no_name_constraints");
  });

  it("rejects an intermediate whose key doesn't match, or that another root signed", async () => {
    const { client } = await signedInClient();
    const root = await createRoot(client);
    const other = await pki.createRootCa({ subject: { commonName: "Lab Root" }, keyAlgorithm: "ECDSA-P256", validityDays: 30, nameConstraints: constraints });
    const foreign = await pki.createIntermediateCa({
      issuer: other.certificate,
      issuerKey: other.keys.privateKey,
      subject: { commonName: "Foreign" },
      keyAlgorithm: "ECDSA-P256",
      validityDays: 30,
    });
    const foreignKey = pki.privateKeyToPem(await pki.exportPrivateKey(foreign.keys.privateKey));
    const r1 = await client.json("/api/cas/intermediates", {
      json: { rootId: root.id, certificatePem: foreign.certificate.toString("pem"), privateKeyPem: foreignKey },
    });
    expect(r1.body.error).toBe("not_signed_by_root");

    const mine = await pki.createIntermediateCa({
      issuer: root.certificate,
      issuerKey: root.keys.privateKey,
      subject: { commonName: "Mine" },
      keyAlgorithm: "ECDSA-P256",
      validityDays: 30,
    });
    const r2 = await client.json("/api/cas/intermediates", {
      json: { rootId: root.id, certificatePem: mine.certificate.toString("pem"), privateKeyPem: foreignKey },
    });
    expect(r2.body.error).toBe("key_mismatch");
  });

  it("keeps each user's CAs private", async () => {
    const alice = await signedInClient();
    const bob = await signedInClient();
    const root = await createRoot(alice.client);
    const inter = await createIntermediate(alice.client, root);
    expect((await bob.client.json(`/api/cas/${root.id}`)).status).toBe(404);
    const { csrPem } = await csrFor("nas.lan", { dns: ["nas.lan"], ip: [] });
    expect((await bob.client.json("/api/certificates", { json: { caId: inter.id, csrPem } })).status).toBe(404);
    expect((await bob.client.json("/api/cas")).body.cas).toEqual([]);
  });
});

describe("issuing, revoking and looking up certificates", () => {
  async function setup() {
    const ctx = await signedInClient();
    const root = await createRoot(ctx.client);
    const inter = await createIntermediate(ctx.client, root);
    return { ...ctx, root, inter };
  }

  it("issues from a CSR within the name constraints, with CRL and AIA URLs", async () => {
    const { client, inter } = await setup();
    const { csrPem } = await csrFor("nas.home.arpa", { dns: ["nas.home.arpa"], ip: ["192.168.1.10"] });
    const res = await client.json("/api/certificates", {
      json: { caId: inter.id, csrPem, validityDays: 90, tags: ["NAS", "storage"], notes: "basement" },
    });
    expect(res.status).toBe(201);
    expect(res.body.certificate).toMatchObject({
      commonName: "nas.home.arpa",
      sans: { dns: ["nas.home.arpa"], ip: ["192.168.1.10"] },
      profile: "server",
      tags: ["nas", "storage"],
      status: "valid",
    });
    expect(res.body.chainPem).toHaveLength(2);
    const cert = new x509.X509Certificate(res.body.certificate.certificatePem);
    const dp = JSON.stringify(cert.getExtension(x509.CRLDistributionPointsExtension)!.distributionPoints);
    expect(dp).toContain(`http://pki-crl.n25tech.com/${inter.id}.crl`);
    expect(cert.getExtension(x509.AuthorityInfoAccessExtension)!.caIssuers[0].value).toBe(`http://pki-crl.n25tech.com/${inter.id}.crt`);
  });

  it("refuses names outside the root's constraints", async () => {
    const { client, inter } = await setup();
    const { csrPem } = await csrFor("google.com", { dns: ["google.com"], ip: [] });
    const res = await client.json("/api/certificates", { json: { caId: inter.id, csrPem } });
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/google\.com/);
    // Overriding the CSR's names doesn't get around it either.
    const res2 = await client.json("/api/certificates", { json: { caId: inter.id, csrPem, sans: { dns: ["nas.lan", "bank.com"] } } });
    expect(res2.status).toBe(400);
  });

  it("filters and searches the inventory", async () => {
    const { client, inter } = await setup();
    for (const name of ["printer.lan", "nas.lan", "router.home.arpa"]) {
      const { csrPem } = await csrFor(name, { dns: [name], ip: [] });
      await client.json("/api/certificates", { json: { caId: inter.id, csrPem, tags: name === "nas.lan" ? ["storage"] : [] } });
    }
    const names = async (qs: string) =>
      (await client.json(`/api/certificates?${qs}`)).body.certificates.map((c: { commonName: string }) => c.commonName).sort();
    expect(await names("")).toEqual(["nas.lan", "printer.lan", "router.home.arpa"]);
    expect(await names("q=home.arpa")).toEqual(["router.home.arpa"]);
    expect(await names("tag=storage")).toEqual(["nas.lan"]);
    expect(await names("q=%25")).toEqual([]);
  });

  it("revokes a certificate and publishes it on the CRL host", async () => {
    const { client, inter } = await setup();
    const { csrPem } = await csrFor("nas.lan", { dns: ["nas.lan"], ip: [] });
    const issued = (await client.json("/api/certificates", { json: { caId: inter.id, csrPem } })).body.certificate;

    const revoked = await client.json(`/api/certificates/${issued.id}/revoke`, { json: { reason: 1 } });
    expect(revoked.body.certificate.status).toBe("revoked");
    expect((await client.json(`/api/certificates/${issued.id}/revoke`, { json: { reason: 1 } })).status).toBe(409);

    const res = await client.fetch(`http://pki-crl.n25tech.com/${inter.id}.crl`);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/pkix-crl");
    const crl = new x509.X509Crl(await res.arrayBuffer());
    expect(await crl.verify({ publicKey: new x509.X509Certificate(inter.res.body.ca.certificatePem).publicKey })).toBe(true);
    expect(crl.entries.map((e) => e.serialNumber)).toEqual([issued.serial]);
    expect(crl.entries[0].reason).toBe(x509.X509CrlReason.keyCompromise);
    expect(pki.crlNumberOf(crl)).toBe(2);

    const crt = await client.fetch(`http://pki-crl.n25tech.com/${inter.id}.crt`);
    expect(crt.headers.get("Content-Type")).toBe("application/pkix-cert");
    expect(await pki.fingerprint(new x509.X509Certificate(await crt.arrayBuffer()))).toBe(inter.res.body.ca.fingerprint);
  });

  it("revokes an intermediate through a root-signed CRL and destroys its key", async () => {
    const { client, root, inter } = await setup();
    const interCert = new x509.X509Certificate(inter.res.body.ca.certificatePem);
    const crl = await pki.createCrl({
      issuer: root.certificate,
      issuerKey: root.keys.privateKey,
      crlNumber: 2,
      entries: [{ serialNumber: interCert.serialNumber, revokedAt: new Date(), reason: x509.X509CrlReason.keyCompromise }],
    });
    const res = await client.json(`/api/cas/${root.id}/crl`, { method: "PUT", json: { crlPem: pki.crlToPem(crl) } });
    expect(res.status).toBe(200);
    expect(res.body.revoked).toEqual([inter.id]);
    const row = await env.DB.prepare("SELECT revoked_at, key_enc FROM cas WHERE id = ?").bind(inter.id).first();
    expect(row).toMatchObject({ key_enc: null });
    expect(row!.revoked_at).toBeTypeOf("number");

    const { csrPem } = await csrFor("nas.lan", { dns: ["nas.lan"], ip: [] });
    expect((await client.json("/api/certificates", { json: { caId: inter.id, csrPem } })).body.error).toBe("ca_revoked");

    // An older CRL number is refused, and the root CRL is served.
    expect((await client.json(`/api/cas/${root.id}/crl`, { method: "PUT", json: { crlPem: pki.crlToPem(crl) } })).body.error).toBe("stale_crl");
    const served = await client.fetch(`http://pki-crl.n25tech.com/${root.id}.crl`);
    expect(served.status).toBe(200);
  });

  it("looks up certificates: in inventory, issued but unknown, revoked, and foreign", async () => {
    const { client, root, inter } = await setup();
    const { csrPem } = await csrFor("nas.lan", { dns: ["nas.lan"], ip: [] });
    const issued = (await client.json("/api/certificates", { json: { caId: inter.id, csrPem } })).body.certificate;

    const found = await client.json("/api/lookup", { json: { certificatePem: issued.certificatePem } });
    expect(found.body).toMatchObject({ result: "issued", status: "valid", certificate: { id: issued.id } });
    expect(found.body.chain.map((c: { id: string }) => c.id)).toEqual([inter.id, root.id]);

    const rootLookup = await client.json("/api/lookup", { json: { certificatePem: root.certificate.toString("pem") } });
    expect(rootLookup.body).toMatchObject({ result: "ca", ca: { id: root.id } });

    await client.json(`/api/certificates/${issued.id}/revoke`, { json: { reason: 4 } });
    expect((await client.json("/api/lookup", { json: { certificatePem: issued.certificatePem } })).body.status).toBe("revoked");

    const bob = await signedInClient();
    expect((await bob.client.json("/api/lookup", { json: { certificatePem: issued.certificatePem } })).body.result).toBe("unknown");
  });
});

describe("account", () => {
  it("exports CAs with intermediate keys, and deletes everything", async () => {
    const { client, email } = await signedInClient();
    const root = await createRoot(client);
    const inter = await createIntermediate(client, root);

    const exp = await client.json("/api/account/export");
    expect(exp.status).toBe(200);
    const exportedInter = exp.body.cas.find((c: { id: string }) => c.id === inter.id);
    expect(exportedInter.privateKeyPem).toBe(inter.privateKeyPem);
    expect(exp.body.cas.find((c: { id: string }) => c.id === root.id).privateKeyPem).toBeNull();

    expect((await client.json("/api/account", { method: "DELETE", json: { confirmEmail: "wrong@example.com" } })).status).toBe(400);
    expect((await client.json("/api/account", { method: "DELETE", json: { confirmEmail: email } })).status).toBe(200);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM cas WHERE id IN (?, ?)").bind(root.id, inter.id).first("n")).toBe(0);
    expect((await client.fetch(`http://pki-crl.n25tech.com/${inter.id}.crl`)).status).toBe(404);
  });

  it("records an audit trail", async () => {
    const { client } = await signedInClient();
    await createRoot(client);
    const events = (await client.json("/api/account/audit")).body.events.map((e: { action: string }) => e.action);
    expect(events).toEqual(expect.arrayContaining(["account.register", "mfa.enabled", "ca.root_created"]));
  });
});

describe("cron", () => {
  it("refreshes intermediate CRLs that are about to expire", async () => {
    const { client, root } = await signedInClient().then(async (ctx) => ({ ...ctx, root: await createRoot(ctx.client) }));
    const inter = await createIntermediate(client, root);
    await env.DB.prepare("UPDATE cas SET crl_next_update = ? WHERE id = ?").bind(Date.now() + 3600_000, inter.id).run();
    const { refreshExpiringCrls } = await import("../src/worker/lib/ca");
    expect(await refreshExpiringCrls(env)).toBeGreaterThanOrEqual(1);
    const row = await env.DB.prepare("SELECT crl_number, crl_next_update FROM cas WHERE id = ?").bind(inter.id).first<{ crl_number: number; crl_next_update: number }>();
    expect(row!.crl_number).toBe(2);
    expect(row!.crl_next_update).toBeGreaterThan(Date.now() + 6 * 86400_000);
  });
});

