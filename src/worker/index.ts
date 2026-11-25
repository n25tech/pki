/**
 * Single Worker serving three hostnames:
 *
 *   pki.n25tech.com       app UI (static assets) + JSON API under /api/*
 *   pki-crl.n25tech.com   CRLs and CA certificates; must work over plain HTTP
 *   pki-acme.n25tech.com  ACME server (Phase 3)
 *
 * Hostnames come from vars in wrangler.jsonc. On local/preview hosts
 * (localhost, *.workers.dev) the app is served at the root and the other two
 * are reachable under /_crl/* and /_acme/* for testing.
 */
import { api } from "./api";
import { crl } from "./crl";
import { acme } from "./acme";
import { withAppSecurityHeaders } from "./headers";

function isDevHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host.endsWith(".workers.dev");
}

function stripPrefix(request: Request, prefix: string): Request {
  const url = new URL(request.url);
  url.pathname = url.pathname.slice(prefix.length) || "/";
  return new Request(url, request);
}

async function serveApp(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
    return withAppSecurityHeaders(await api.fetch(request, env, ctx), url);
  }
  return withAppSecurityHeaders(await env.ASSETS.fetch(request), url);
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);
    const host = url.hostname;

    if (host === env.CRL_HOST) return crl.fetch(request, env, ctx);
    if (host === env.ACME_HOST) return acme.fetch(request, env, ctx);

    if (host === env.APP_HOST) {
      if (url.protocol === "http:") {
        url.protocol = "https:";
        return Response.redirect(url.toString(), 301);
      }
      return serveApp(request, env, ctx);
    }

    if (isDevHost(host)) {
      if (url.pathname.startsWith("/_crl/")) return crl.fetch(stripPrefix(request, "/_crl"), env, ctx);
      if (url.pathname.startsWith("/_acme/")) return acme.fetch(stripPrefix(request, "/_acme"), env, ctx);
      return serveApp(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
