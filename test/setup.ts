import { applyD1Migrations, type D1Migration } from "cloudflare:test";
import { env } from "cloudflare:workers";

await applyD1Migrations(env.DB, (env as unknown as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS);

// Mock Turnstile's siteverify endpoint (the Worker runs in this same isolate).
// Token "pass:<action>" succeeds for that action; anything else fails.
import { vi } from "vitest";
const realFetch = globalThis.fetch;
vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (url === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
    const params = new URLSearchParams(String(init?.body ?? ""));
    const [verdict, action] = (params.get("response") ?? "").split(":");
    const ok = verdict === "pass" && params.get("secret") === "test-secret-key";
    return Response.json(ok ? { success: true, action } : { success: false, "error-codes": ["invalid-input-response"] });
  }
  if (url === "https://oauth2.googleapis.com/token") {
    // The test passes the desired ID-token claims as the authorization code.
    const code = new URLSearchParams(String(init?.body ?? "")).get("code") ?? "";
    const claims = { iss: "https://accounts.google.com", aud: "test-client-id", exp: Math.floor(Date.now() / 1000) + 600, ...JSON.parse(atob(code)) };
    const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    return Response.json({ id_token: `${b64({ alg: "none" })}.${b64(claims)}.sig` });
  }
  return realFetch(input, init);
});
