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
    // "pass:<action>:<hostname>" lets a test pick the hostname; it defaults to the allowed one.
    const hostname = (params.get("response") ?? "").split(":")[2] ?? "pki.n25tech.com";
    return Response.json(ok ? { success: true, action, hostname } : { success: false, "error-codes": ["invalid-input-response"] });
  }
  return realFetch(input, init);
});
