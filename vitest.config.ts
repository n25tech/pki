import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

// Tests run inside workerd, the same runtime as production.
export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
  test: {
    // RSA key generation and the first workerd start can be slow on CI runners.
    testTimeout: 20_000,
  },
});
