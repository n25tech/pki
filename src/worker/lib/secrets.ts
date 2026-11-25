/**
 * Everything secret is derived from a single MASTER_KEY (32 random bytes,
 * base64) with HKDF, so there is only one secret to manage and rotate:
 *
 *   "pki/keywrap/v1"   AES-256-GCM key that encrypts CA private keys and TOTP secrets
 *   "pki/pepper/v1"    HMAC key mixed into password hashes
 *   "pki/cookie/v1"    HMAC key that signs short-lived cookies (OAuth state)
 */
import { fromBase64, toBase64, toBase64Url } from "./util";

type Purpose = "keywrap" | "pepper" | "cookie";

const cache = new Map<string, Promise<CryptoKey>>();

function masterKeyBytes(env: Env): Uint8Array {
  if (!env.MASTER_KEY) throw new Error("MASTER_KEY secret is not set");
  const bytes = fromBase64(env.MASTER_KEY.trim());
  if (bytes.length < 32) throw new Error("MASTER_KEY must be at least 32 bytes (base64)");
  return bytes;
}

async function derive(env: Env, purpose: Purpose): Promise<CryptoKey> {
  const cacheKey = `${env.MASTER_KEY}|${purpose}`;
  let key = cache.get(cacheKey);
  if (!key) {
    key = (async () => {
      const ikm = await crypto.subtle.importKey("raw", masterKeyBytes(env), "HKDF", false, ["deriveKey"]);
      const params = {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(`pki/${purpose}/v1`),
      };
      return purpose === "keywrap"
        ? crypto.subtle.deriveKey(params, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"])
        : crypto.subtle.deriveKey(params, ikm, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign", "verify"]);
    })();
    cache.set(cacheKey, key);
  }
  return key;
}

/**
 * Encrypts `plaintext`, binding it to `context` (e.g. "ca:<id>:<user>") as
 * additional authenticated data, so a ciphertext copied to another row fails
 * to decrypt. Output: "v1.<iv b64>.<ciphertext b64>".
 */
export async function seal(env: Env, plaintext: Uint8Array, context: string): Promise<string> {
  const key = await derive(env, "keywrap");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(context) },
    key,
    plaintext,
  );
  return `v1.${toBase64(iv)}.${toBase64(ct)}`;
}

export async function unseal(env: Env, sealed: string, context: string): Promise<Uint8Array> {
  const [version, iv, ct] = sealed.split(".");
  if (version !== "v1" || !iv || !ct) throw new Error("Unsupported sealed value");
  const key = await derive(env, "keywrap");
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(iv), additionalData: new TextEncoder().encode(context) },
    key,
    fromBase64(ct),
  );
  return new Uint8Array(pt);
}

export async function hmac(env: Env, purpose: "pepper" | "cookie", data: string | Uint8Array): Promise<Uint8Array> {
  const key = await derive(env, purpose);
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
}

/** Signs a value for a cookie: "<value b64url>.<mac b64url>". */
export async function signCookieValue(env: Env, value: string): Promise<string> {
  const payload = toBase64Url(new TextEncoder().encode(value));
  const mac = toBase64Url(await hmac(env, "cookie", payload));
  return `${payload}.${mac}`;
}

export async function verifyCookieValue(env: Env, signed: string | undefined): Promise<string | null> {
  if (!signed) return null;
  const [payload, mac] = signed.split(".");
  if (!payload || !mac) return null;
  const key = await derive(env, "cookie");
  const ok = await crypto.subtle.verify("HMAC", key, fromBase64(mac), new TextEncoder().encode(payload));
  return ok ? new TextDecoder().decode(fromBase64(payload)) : null;
}
