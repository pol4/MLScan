import { defineConfig } from "@playwright/test";

const baseURL = process.env.E2E_BASE_URL || "http://127.0.0.1:18080";

// e2e гоняются против analytics напрямую (BFF), эмуляция заголовков oauth2-proxy.
// Внимание: локальный `kubectl port-forward` плохо переносит параллельные соединения, поэтому
// по умолчанию 1 воркер; на «холодном» старте возможны таймауты — включён 1 ретрай.
export default defineConfig({
  testDir: "tests/e2e",
  timeout: 60000,
  expect: { timeout: 15000 },
  retries: process.env.CI ? 2 : 1,
  workers: 1,
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
