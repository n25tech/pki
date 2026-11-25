import { exports } from "cloudflare:workers";
import * as pki from "../src/shared/pki";
import { totpAt, currentStep } from "../src/worker/lib/totp";

export const APP = "https://pki.n25tech.com";

/** A browser-like client: keeps cookies and sends a same-origin Origin header. */
export class Client {
  cookies = new Map<string, string>();

  async fetch(path: string, init: RequestInit & { json?: unknown } = {}) {
    const headers = new Headers(init.headers);
    if (this.cookies.size) headers.set("Cookie", [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "));
    const method = init.method ?? (init.json !== undefined ? "POST" : "GET");
    if (method !== "GET" && !headers.has("Origin")) headers.set("Origin", APP);
    let body = init.body;
    if (init.json !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(init.json);
    }
    const url = path.startsWith("http") ? path : `${APP}${path}`;
    const res = await exports.default.fetch(new Request(url, { ...init, method, headers, body, redirect: "manual" }));
    for (const set of res.headers.getSetCookie()) {
      const [pair, ...attrs] = set.split(";");
      const [name, value] = pair.split("=");
      const expired = attrs.some((a) => /max-age=0/i.test(a.trim()) || /expires=thu, 01 jan 1970/i.test(a.trim()));
      if (expired || !value) this.cookies.delete(name.trim());
      else this.cookies.set(name.trim(), value);
    }
    return res;
  }

  async json<T = any>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<{ status: number; body: T }> {
    const res = await this.fetch(path, init);
    return { status: res.status, body: (await res.json()) as T };
  }
}

let counter = 0;
export function uniqueEmail() {
  return `user${Date.now()}-${counter++}@example.com`;
}

/** A code for the next time step: enrolment used the current one, and codes can't be reused. */
export async function nextTotp(secret: string) {
  return totpAt(secret, currentStep() + 1);
}

/** Registers, enables 2FA, and returns a client with a fully authenticated session. */
export async function signedInClient(email = uniqueEmail(), password = "correct horse battery staple") {
  const client = new Client();
  await client.json("/api/auth/register", { json: { turnstileToken: "pass:register", email, password } });
  const setup = await client.json<{ secret: string }>("/api/auth/totp/setup", { json: {} });
  const enabled = await client.json<{ recoveryCodes: string[] }>("/api/auth/totp/enable", {
    json: { code: await totpAt(setup.body.secret, currentStep()) },
  });
  return { client, email, password, secret: setup.body.secret, recoveryCodes: enabled.body.recoveryCodes };
}

export const constraints = { dns: ["home.arpa", "lan"], ip: ["192.168.0.0/16"] };

/** Does what the browser does: generates a root and registers it with its key. */
export async function createRoot(client: Client, nc = constraints) {
  const root = await pki.createRootCa({
    subject: { commonName: "Lab Root" },
    keyAlgorithm: "ECDSA-P256",
    validityDays: 3650,
    nameConstraints: nc,
  });
  const privateKeyPem = pki.privateKeyToPem(await pki.exportPrivateKey(root.keys.privateKey));
  const res = await client.json("/api/cas/roots", {
    json: { name: "Lab root", certificatePem: root.certificate.toString("pem"), privateKeyPem },
  });
  return { ...root, res, privateKeyPem, id: res.body?.ca?.id as string };
}

/** Generates an intermediate key pair "in the browser" and has the server sign it with the root. */
export async function createIntermediate(client: Client, root: { id: string }, validityDays = 1825) {
  const keys = await pki.generateKeyPair("ECDSA-P256");
  const csr = await pki.createCsr(keys, "Lab Issuing CA", { dns: [], ip: [] });
  const privateKeyPem = pki.privateKeyToPem(await pki.exportPrivateKey(keys.privateKey));
  const res = await client.json("/api/cas/intermediates", {
    json: { rootId: root.id, name: "Issuing", csrPem: csr.toString("pem"), privateKeyPem, validityDays },
  });
  return { keys, res, id: res.body?.ca?.id as string, privateKeyPem };
}

export async function csrFor(commonName: string, sans: pki.SubjectAltNames, alg: pki.KeyAlgorithm = "ECDSA-P256") {
  const keys = await pki.generateKeyPair(alg);
  const csr = await pki.createCsr(keys, commonName, sans);
  return { keys, csrPem: csr.toString("pem") };
}

/** Runs the Google sign-in redirect flow; Google's token endpoint is mocked in setup.ts. */
export async function googleSignIn(client: Client, claims: { sub: string; email: string; email_verified?: boolean }) {
  const start = await client.fetch("/api/auth/google/start");
  const state = new URL(start.headers.get("Location")!).searchParams.get("state")!;
  const code = btoa(JSON.stringify({ email_verified: true, ...claims }));
  const res = await client.fetch(`/api/auth/google/callback?code=${encodeURIComponent(code)}&state=${state}`);
  return { status: res.status, location: res.headers.get("Location") };
}
