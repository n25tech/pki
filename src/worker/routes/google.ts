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
      // Google has verified the address, so it's safe to link it to the account with that email.
      // If that account never verified its email, whoever created it may not own the address
      // (account pre-hijacking), so their password, 2FA and sessions are removed.
      const unverified = !byEmail.email_verified_at;
      await db.batch([
        unverified
          ? db.prepare(
              `UPDATE users SET google_sub = ?, email_verified_at = ?, password_hash = NULL,
                 totp_secret_enc = NULL, totp_enabled_at = NULL, totp_last_step = NULL WHERE id = ?`,
            ).bind(claims.sub, now(), byEmail.id)
          : db.prepare("UPDATE users SET google_sub = ? WHERE id = ?").bind(claims.sub, byEmail.id),
        ...(unverified
          ? [
              db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(byEmail.id),
              db.prepare("DELETE FROM recovery_codes WHERE user_id = ?").bind(byEmail.id),
            ]
          : []),
      ]);
      await audit(c, byEmail.id, "account.google_linked", null, { resetUnverifiedCredentials: unverified });
      user = (await db.prepare("SELECT * FROM users WHERE id = ?").bind(byEmail.id).first<UserRow>())!;
    } else {
      const id = randomId();
      await db.prepare("INSERT INTO users (id, email, email_verified_at, google_sub, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(id, email, now(), claims.sub, now())
        .run();
      await audit(c, id, "account.register", null, { method: "google" });
      user = (await db.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>())!;
    }
  }

  await destroySession(c);
  await createSession(c, user.id, false);
  await audit(c, user.id, "login.google");
  return c.redirect(user.totp_enabled_at ? "/login/mfa" : "/", 302);
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
