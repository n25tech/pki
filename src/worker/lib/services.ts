import type { AppContext } from "./context";
import { clientIp, fail, now } from "./util";

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export async function audit(
  c: AppContext,
  userId: string | null,
  action: string,
  target?: string | null,
  meta?: Record<string, unknown>,
): Promise<void> {
  await c.env.DB.prepare("INSERT INTO audit_log (user_id, action, target, meta, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(userId, action, target ?? null, meta ? JSON.stringify(meta) : null, clientIp(c.req.raw), now())
    .run();
}

// ---------------------------------------------------------------------------
// Rate limiting (Workers rate limiting binding; a no-op if not bound)
// ---------------------------------------------------------------------------

export async function rateLimit(c: AppContext, scope: string, subject = ""): Promise<void> {
  const limiter = c.env.AUTH_LIMITER;
  if (!limiter) return;
  const { success } = await limiter.limit({ key: `${scope}:${clientIp(c.req.raw)}:${subject.toLowerCase()}` });
  if (!success) fail(429, "rate_limited", "Too many attempts. Wait a minute and try again.");
}

// ---------------------------------------------------------------------------
// Email (Resend if RESEND_API_KEY is set, otherwise logged)
// ---------------------------------------------------------------------------

export interface Email {
  to: string;
  subject: string;
  text: string;
}

export async function sendEmail(env: Env, email: Email): Promise<void> {
  if (!env.RESEND_API_KEY) {
    console.log(`[email not sent: RESEND_API_KEY unset] to=${email.to} subject=${email.subject}\n${email.text}`);
    return;
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.EMAIL_FROM, to: [email.to], subject: email.subject, text: email.text }),
  });
  if (!res.ok) console.error(`Email send failed: ${res.status} ${await res.text()}`);
}

/** The origin links in emails should point at: the app host in production, the request origin elsewhere. */
export function appOrigin(c: AppContext): string {
  const url = new URL(c.req.url);
  return url.hostname === c.env.APP_HOST ? `https://${c.env.APP_HOST}` : url.origin;
}

// ---------------------------------------------------------------------------
// Cloudflare Turnstile (bot check on sign-up and password-reset requests)
// ---------------------------------------------------------------------------

export function turnstileEnabled(env: Env): boolean {
  return !!env.TURNSTILE_SITE_KEY && !!env.TURNSTILE_SECRET_KEY;
}

/** Verifies a Turnstile token for `action`. A no-op when Turnstile isn't configured. */
export async function verifyTurnstile(c: AppContext, token: unknown, action: string): Promise<void> {
  if (!turnstileEnabled(c.env)) return;
  if (typeof token !== "string" || !token || token.length > 2048) {
    fail(400, "turnstile_required", "Please complete the check that you're human");
  }
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: new URLSearchParams({ secret: c.env.TURNSTILE_SECRET_KEY!, response: token, remoteip: clientIp(c.req.raw) }),
  });
  const data = (await res.json().catch(() => ({}))) as { success?: boolean; action?: string; "error-codes"?: string[] };
  // Tokens are single-use and tied to the action they were issued for.
  if (!data.success || (data.action && data.action !== action)) {
    console.log(`turnstile rejected: action=${action} errors=${(data["error-codes"] ?? []).join(",")}`);
    fail(400, "turnstile_failed", "The human check failed or expired. Please try again.");
  }
}
