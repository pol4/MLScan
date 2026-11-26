import { defineConfig } from "@playwright/test";

const baseURL = process.env.E2E_BASE_URL || "http://127.0.0.1:18080";

// e2e гоняются против analytics напрямую (BFF), эмулируя заголовки oauth2-proxy.
export default defineConfig({
  testDir: "tests/e2e",
  timeout: 30000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: {
      "X-Forwarded-User": process.env.E2E_USER || "admin",
      "X-Forwarded-Groups": process.env.E2E_GROUPS || "mlscan-admins",
      "X-Forwarded-Email": "admin@platform.rtx.local",
    },
  },
});
