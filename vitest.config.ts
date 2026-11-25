import path from "node:path";
import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";

// Tests run inside workerd, the same runtime as production, against a local D1.
export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          TEST_MIGRATIONS: await readD1Migrations(path.join(__dirname, "migrations")),
          // Test-only key. Production uses the MASTER_KEY secret.
          MASTER_KEY: "dGVzdC1tYXN0ZXIta2V5LW5vdC1mb3ItcHJvZHVjdGlvbiE=",
          // Turnstile on, with verification mocked in test/setup.ts.
          TURNSTILE_SITE_KEY: "test-site-key",
          TURNSTILE_SECRET_KEY: "test-secret-key",
          // Google sign-in on, with Google's token endpoint mocked in test/setup.ts.
          GOOGLE_CLIENT_ID: "test-client-id",
          GOOGLE_CLIENT_SECRET: "test-client-secret",
        },
      },
    })),
  ],
  test: {
    setupFiles: ["./test/setup.ts"],
    // RSA key generation and the first workerd start can be slow on CI runners.
    testTimeout: 20_000,
  },
});
