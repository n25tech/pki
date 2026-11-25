/**
 * Password hashing with PBKDF2-HMAC-SHA256 from WebCrypto.
 *
 * The Workers runtime caps PBKDF2 at 100,000 iterations, below OWASP's
 * recommendation for PBKDF2 alone. To make up for it, the password is first
 * HMAC'd with a pepper derived from MASTER_KEY, so a database dump without the
 * Worker secret can't be brute-forced at all. The format records its parameters
 * so hashes can be upgraded later.
 */
import { hmac } from "./secrets";
import { fromBase64, randomBytes, timingSafeEqual, toBase64 } from "./util";

const ITERATIONS = 100_000;
export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 256;

async function derive(env: Env, password: string, salt: Uint8Array, iterations: number): Promise<string> {
  const peppered = await hmac(env, "pepper", password.normalize("NFKC"));
  const key = await crypto.subtle.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return toBase64(bits);
}

export async function hashPassword(env: Env, password: string): Promise<string> {
  const salt = randomBytes(16);
  return `pbkdf2-sha256$${ITERATIONS}$${toBase64(salt)}$${await derive(env, password, salt, ITERATIONS)}`;
}

export async function verifyPassword(env: Env, password: string, stored: string | null): Promise<boolean> {
  // Always do the work, so timing doesn't reveal whether the account exists.
  const [scheme, iter, salt, hash] = (stored ?? `pbkdf2-sha256$${ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA==$`).split("$");
  if (scheme !== "pbkdf2-sha256") return false;
  const computed = await derive(env, password, fromBase64(salt), Number(iter));
  return stored !== null && timingSafeEqual(computed, hash);
}

export function passwordProblem(password: unknown): string | null {
  if (typeof password !== "string") return "Password is required";
  if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  if (password.length > MAX_PASSWORD_LENGTH) return `Password must be at most ${MAX_PASSWORD_LENGTH} characters`;
  return null;
}
