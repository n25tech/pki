const CSP = [
  "default-src 'self'",
  // Cloudflare Turnstile's script and challenge iframe.
  "script-src 'self' https://challenges.cloudflare.com",
  "frame-src https://challenges.cloudflare.com",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

/**
 * Security headers for the app hostname only. HSTS deliberately omits
 * includeSubDomains: the CRL host must stay reachable over plain HTTP.
 */
export function withAppSecurityHeaders(response: Response, url: URL): Response {
  const res = new Response(response.body, response);
  const h = res.headers;
  h.set("Content-Security-Policy", CSP);
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Referrer-Policy", "strict-origin-when-cross-origin");
  h.set("X-Frame-Options", "DENY");
  h.set("Cross-Origin-Opener-Policy", "same-origin");
  h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  if (url.protocol === "https:") h.set("Strict-Transport-Security", "max-age=31536000");
  return res;
}
