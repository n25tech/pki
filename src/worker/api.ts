import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import type { AppEnv } from "./lib/context";
import { loadSession, requireAuth, requireMfa } from "./lib/session";
import { fail } from "./lib/util";
import { account, lookup } from "./routes/account";
import { auth } from "./routes/auth";
import { cas } from "./routes/cas";
import { certificates, REVOCATION_REASONS } from "./routes/certificates";
import { google } from "./routes/google";
import { MAX_LEAF_VALIDITY_DAYS } from "../shared/pki";
import { turnstileEnabled } from "./lib/services";

export const api = new Hono<AppEnv>().basePath("/api");

api.use("*", async (c, next) => {
  c.header("Cache-Control", "no-store");
  await next();
});

/**
 * CSRF protection: state-changing requests must come from our own origin.
 * (Session cookies are also SameSite=Lax.)
 */
api.use("*", async (c, next) => {
  if (!["GET", "HEAD", "OPTIONS"].includes(c.req.method)) {
    const origin = c.req.header("Origin");
    if (!origin || origin !== new URL(c.req.url).origin) fail(403, "bad_origin", "Cross-origin request refused");
  }
  await next();
});

api.use("*", loadSession);

api.get("/health", (c) => c.json({ ok: true }));

api.get("/config", (c) =>
  c.json({
    googleEnabled: !!c.env.GOOGLE_CLIENT_ID && !!c.env.GOOGLE_CLIENT_SECRET,
    emailEnabled: !!c.env.RESEND_API_KEY,
    turnstileSiteKey: turnstileEnabled(c.env) ? c.env.TURNSTILE_SITE_KEY : null,
    crlBaseUrl: `http://${c.env.CRL_HOST}`,
    maxLeafValidityDays: MAX_LEAF_VALIDITY_DAYS,
    revocationReasons: REVOCATION_REASONS,
  }),
);

api.route("/auth", auth);
api.route("/auth/google", google);

// Everything below needs a signed-in user...
api.use("/account/*", requireAuth);
api.use("/account", requireAuth);
// ...and CA work additionally needs two-factor authentication.
api.use("/cas/*", requireMfa);
api.use("/cas", requireMfa);
api.use("/certificates/*", requireMfa);
api.use("/certificates", requireMfa);
api.use("/account/export", requireMfa);
api.use("/lookup", requireMfa);

api.route("/cas", cas);
api.route("/certificates", certificates);
api.route("/account", account);
api.route("/lookup", lookup);

api.notFound((c) => c.json({ error: "not_found", message: "Not found" }, 404));

api.onError((err, c) => {
  if (err instanceof HTTPException) return err.getResponse();
  console.error(err);
  return c.json({ error: "internal_error", message: "Something went wrong" }, 500);
});
