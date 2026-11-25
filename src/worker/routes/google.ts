/**
 * Google sign-in (OpenID Connect authorization code flow with PKCE).
 *
 * State and the PKCE verifier live in a short-lived signed cookie. The ID token
 * comes straight from Google's token endpoint over TLS, which OIDC allows the
 * client to trust without verifying its signature (OIDC Core §3.1.3.7).
 */
import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppContext, AppEnv, UserRow } from "../lib/context";
import { signCookieValue, verifyCookieValue } from "../lib/secrets";
import { appOrigin, audit, rateLimit } from "../lib/services";
import { verifyPassword } from "../lib/password";
import { readJson } from "./json";
import { createSession, destroySession } from "../lib/session";
import { fail, fromBase64, now, randomId, randomToken, toBase64Url } from "../lib/util";

export const google = new Hono<AppEnv>();

const OAUTH_COOKIE = "__Host-pki_oauth";

function redirectUri(c: AppContext) {
  return `${appOrigin(c)}/api/auth/google/callback`;
}

function enabled(env: Env) {
  return !!env.GOOGLE_CLIENT_ID && !!env.GOOGLE_CLIENT_SECRET;
}

google.get("/start", async (c) => {
  if (!enabled(c.env)) fail(404, "google_disabled", "Google sign-in isn't configured");
  await rateLimit(c, "oauth");
  const state = randomToken(16);
  const verifier = randomToken(32);
  const challenge = toBase64Url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  setCookie(c, OAUTH_COOKIE, await signCookieValue(c.env, JSON.stringify({ state, verifier, t: now() })), {
    path: "/",
    secure: true,
    httpOnly: true,
    // Lax so the cookie comes back on Google's top-level redirect.
    sameSite: "Lax",
    maxAge: 600,
  });
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: c.env.GOOGLE_CLIENT_ID!,
    redirect_uri: redirectUri(c),
    response_type: "code",
    scope: "openid email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  }).toString();
  return c.redirect(url.toString(), 302);
});

google.get("/callback", async (c) => {
  if (!enabled(c.env)) fail(404, "google_disabled");
  const back = (reason: string) => c.redirect(`/login?error=${encodeURIComponent(reason)}`, 302);

  const saved = await verifyCookieValue(c.env, getCookie(c, OAUTH_COOKIE));
  deleteCookie(c, OAUTH_COOKIE, { path: "/", secure: true });
  const { state, verifier, t } = saved ? (JSON.parse(saved) as { state: string; verifier: string; t: number }) : ({} as never);
  const code = c.req.query("code");
  if (!saved || !code || c.req.query("state") !== state || now() - t > 600_000) return back("google_state");

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: c.env.GOOGLE_CLIENT_ID!,
      client_secret: c.env.GOOGLE_CLIENT_SECRET!,
      redirect_uri: redirectUri(c),
      grant_type: "authorization_code",
      code_verifier: verifier,
    }),
  });
  if (!tokenRes.ok) return back("google_token");
  const { id_token } = (await tokenRes.json()) as { id_token?: string };
  const claims = parseIdToken(id_token);
  if (
    !claims ||
    claims.aud !== c.env.GOOGLE_CLIENT_ID ||
    !["https://accounts.google.com", "accounts.google.com"].includes(claims.iss) ||
    claims.exp * 1000 < now() ||
    !claims.sub
  ) {
    return back("google_token");
  }
  if (!claims.email || claims.email_verified !== true) return back("google_unverified");
  const email = claims.email.toLowerCase();

  const db = c.env.DB;
  let user = await db.prepare("SELECT * FROM users WHERE google_sub = ?").bind(claims.sub).first<UserRow>();
  if (!user) {
    const byEmail = await db.prepare("SELECT * FROM users WHERE email = ?").bind(email).first<UserRow>();
    if (byEmail) {
      if (byEmail.google_sub) return back("google_mismatch");
      if (!byEmail.email_verified_at) {
        // Someone created a password account with this email but never verified it, so we
        // don't know whether it's this person's. Ask them: prove it with the password, or
        // replace it (see /link and /replace below).
        setCookie(c, LINK_COOKIE, await signCookieValue(c.env, JSON.stringify({ sub: claims.sub, email, userId: byEmail.id, t: now() } satisfies PendingLink)), {
          path: "/",
          secure: true,
          httpOnly: true,
          sameSite: "Lax",
          maxAge: PENDING_TTL_MS / 1000,
        });
        return c.redirect("/login/google-link", 302);
      }
      // Verified by both us and Google: the same person, so link directly.
      await db.prepare("UPDATE users SET google_sub = ? WHERE id = ?").bind(claims.sub, byEmail.id).run();
      await audit(c, byEmail.id, "account.google_linked");
      user = { ...byEmail, google_sub: claims.sub };
    } else {
      user = await createGoogleUser(c, claims.sub, email);
    }
  }
  return signIn(c, user, "redirect");
});

// --- Linking to an existing, unverified account ------------------------------

const LINK_COOKIE = "__Host-pki_glink";
const PENDING_TTL_MS = 10 * 60_000;

interface PendingLink {
  sub: string;
  email: string;
  userId: string;
  t: number;
}

async function createGoogleUser(c: AppContext, sub: string, email: string): Promise<UserRow> {
  const id = randomId();
  await c.env.DB.prepare("INSERT INTO users (id, email, email_verified_at, google_sub, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(id, email, now(), sub, now())
    .run();
  await audit(c, id, "account.register", null, { method: "google" });
  return (await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>())!;
}

/** Starts a fresh session. 2FA is still required afterwards, for Google sign-ins too. */
async function signIn(c: AppContext, user: UserRow, mode: "redirect" | "json"): Promise<Response> {
  await destroySession(c);
  await createSession(c, user.id, false);
  await audit(c, user.id, "login.google");
  if (mode === "json") return c.json({ mfaRequired: !!user.totp_enabled_at });
  return c.redirect(user.totp_enabled_at ? "/login/mfa" : "/", 302);
}

/** The pending link from the signed cookie, if it's still valid and the account is still unverified. */
async function pendingLink(c: AppContext): Promise<{ pending: PendingLink; existing: UserRow }> {
  const raw = await verifyCookieValue(c.env, getCookie(c, LINK_COOKIE));
  const pending = raw ? (JSON.parse(raw) as PendingLink) : null;
  if (!pending || now() - pending.t > PENDING_TTL_MS) fail(400, "link_expired", "This sign-in expired. Continue with Google again.");
  const existing = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(pending.userId).first<UserRow>();
  if (!existing || existing.email.toLowerCase() !== pending.email || existing.google_sub) {
    deleteCookie(c, LINK_COOKIE, { path: "/", secure: true });
    fail(409, "link_stale", "This account changed in the meantime. Continue with Google again.");
  }
  return { pending, existing };
}

google.get("/pending", async (c) => {
  const { pending, existing } = await pendingLink(c);
  return c.json({ email: pending.email, createdAt: existing.created_at, hasPassword: !!existing.password_hash });
});

/** "It's mine": prove it with the account's password, then link Google and sign in. */
google.post("/link", async (c) => {
  const { pending, existing } = await pendingLink(c);
  await rateLimit(c, "login", pending.email);
  const b = await readJson<{ password: string }>(c);
  if (!(await verifyPassword(c.env, String(b.password ?? ""), existing.password_hash))) {
    await audit(c, existing.id, "login.failed", null, { method: "google_link" });
    fail(401, "invalid_credentials", "That password isn't correct for this account");
  }
  // Google has verified the address, so the email counts as verified now.
  await c.env.DB.prepare("UPDATE users SET google_sub = ?, email_verified_at = COALESCE(email_verified_at, ?) WHERE id = ?")
    .bind(pending.sub, now(), existing.id)
    .run();
  deleteCookie(c, LINK_COOKIE, { path: "/", secure: true });
  await audit(c, existing.id, "account.google_linked", null, { via: "password" });
  return signIn(c, { ...existing, google_sub: pending.sub }, "json");
});

/**
 * "It's not mine": delete the unverified account and everything in it, then
 * create a new account for this Google login.
 */
google.post("/replace", async (c) => {
  const { pending, existing } = await pendingLink(c);
  const b = await readJson<{ confirm: boolean }>(c);
  if (b.confirm !== true) fail(400, "confirmation_required", "Confirm that the existing account should be deleted");
  // Re-check inside the delete: only remove it if it's still unverified and unlinked.
  const deleted = await c.env.DB.prepare(
    "DELETE FROM users WHERE id = ? AND email_verified_at IS NULL AND google_sub IS NULL RETURNING id",
  )
    .bind(existing.id)
    .first();
  if (!deleted) fail(409, "link_stale", "This account changed in the meantime. Continue with Google again.");
  console.log(`unverified account ${existing.id} replaced by a Google sign-in`);
  deleteCookie(c, LINK_COOKIE, { path: "/", secure: true });
  const user = await createGoogleUser(c, pending.sub, pending.email);
  await audit(c, user.id, "account.replaced_unverified", null, { replaced: existing.id });
  return signIn(c, user, "json");
});

google.post("/cancel", (c) => {
  deleteCookie(c, LINK_COOKIE, { path: "/", secure: true });
  return c.json({ ok: true });
});

interface IdTokenClaims {
  iss: string;
  aud: string;
  sub: string;
  exp: number;
  email?: string;
  email_verified?: boolean;
}

function parseIdToken(token: string | undefined): IdTokenClaims | null {
  try {
    const payload = token?.split(".")[1];
    return payload ? (JSON.parse(new TextDecoder().decode(fromBase64(payload))) as IdTokenClaims) : null;
  } catch {
    return null;
  }
}
