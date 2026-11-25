/**
 * Cookie sessions. The cookie holds a random token; the database stores only
 * its SHA-256, so a database leak doesn't hand out live sessions.
 *
 * A session has two levels:
 *   signed in    password or Google verified
 *   mfa          the second factor was also verified (required for any CA work)
 */
import { createMiddleware } from "hono/factory";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppContext, AppEnv, SessionInfo, UserRow } from "./context";
import { clientIp, fail, now, randomToken, sha256Hex } from "./util";

export const SESSION_COOKIE = "__Host-pki_session";
const SESSION_TTL_MS = 30 * 24 * 3600_000;
const IDLE_TTL_MS = 7 * 24 * 3600_000;

export async function createSession(c: AppContext, userId: string, mfa: boolean): Promise<void> {
  const token = randomToken();
  const t = now();
  await c.env.DB.prepare(
    `INSERT INTO sessions (id, user_id, mfa_at, created_at, expires_at, last_seen_at, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      await sha256Hex(token),
      userId,
      mfa ? t : null,
      t,
      t + SESSION_TTL_MS,
      t,
      clientIp(c.req.raw),
      (c.req.header("User-Agent") ?? "").slice(0, 300),
    )
    .run();
  setCookie(c, SESSION_COOKIE, token, {
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax",
    maxAge: SESSION_TTL_MS / 1000,
  });
}

export async function destroySession(c: AppContext): Promise<void> {
  const token = getCookie(c, SESSION_COOKIE);
  if (token) await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(await sha256Hex(token)).run();
  deleteCookie(c, SESSION_COOKIE, { path: "/", secure: true });
}

export async function markSessionMfa(c: AppContext): Promise<void> {
  const s = c.get("session");
  if (!s) return;
  await c.env.DB.prepare("UPDATE sessions SET mfa_at = ? WHERE id = ?").bind(now(), s.id).run();
  s.mfaAt = now();
}

/** Ends every session for a user except, optionally, the current one. */
export async function destroyOtherSessions(c: AppContext, userId: string, keepCurrent: boolean): Promise<void> {
  const current = c.get("session");
  if (keepCurrent && current) {
    await c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?").bind(userId, current.id).run();
  } else {
    await c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();
  }
}

/** Loads the session (if any) into c.var.session. Never rejects. */
export const loadSession = createMiddleware<AppEnv>(async (c, next) => {
  c.set("session", null);
  const token = getCookie(c, SESSION_COOKIE);
  if (token) {
    const id = await sha256Hex(token);
    const t = now();
    const row = await c.env.DB.prepare(
      `SELECT s.id AS sid, s.mfa_at, s.created_at AS s_created, s.expires_at, s.last_seen_at, u.*
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?`,
    )
      .bind(id)
      .first<UserRow & { sid: string; mfa_at: number | null; s_created: number; expires_at: number; last_seen_at: number }>();
    if (row && row.expires_at > t && row.last_seen_at + IDLE_TTL_MS > t) {
      const { sid, mfa_at, s_created, expires_at: _e, last_seen_at, ...user } = row;
      c.set("session", { id: sid, user, mfaAt: mfa_at, createdAt: s_created } satisfies SessionInfo);
      if (t - last_seen_at > 3600_000) {
        c.executionCtx.waitUntil(c.env.DB.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").bind(t, sid).run());
      }
    } else if (row) {
      await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(id).run();
    }
  }
  await next();
});

/** True when the session has passed every factor the user has enabled. */
export function isFullyAuthenticated(s: SessionInfo | null): s is SessionInfo {
  return !!s && (!s.user.totp_enabled_at || !!s.mfaAt);
}

/** Signed in, and past the second factor if the user has one. */
export const requireAuth = createMiddleware<AppEnv>(async (c, next) => {
  const s = c.get("session");
  if (!s) fail(401, "unauthenticated", "Please sign in");
  if (!isFullyAuthenticated(s)) fail(401, "mfa_required", "Enter your authentication code");
  await next();
});

/** Signed in with two-factor enabled and verified. Required for all CA and certificate work. */
export const requireMfa = createMiddleware<AppEnv>(async (c, next) => {
  const s = c.get("session");
  if (!s) fail(401, "unauthenticated", "Please sign in");
  if (!s.user.totp_enabled_at) fail(403, "mfa_setup_required", "Set up two-factor authentication first");
  if (!s.mfaAt) fail(401, "mfa_required", "Enter your authentication code");
  await next();
});

export function currentUser(c: AppContext): UserRow {
  const s = c.get("session");
  if (!s) fail(401, "unauthenticated");
  return s.user;
}
