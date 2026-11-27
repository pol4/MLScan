import { test, expect } from "@playwright/test";

// Локализация: EN-локаль (localStorage.mlscan_lang) — английские подписи навигации/экранов.

test.use({ locale: "en-US" });

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => { try { localStorage.setItem("mlscan_lang", "en"); } catch {} });
});

test("EN-локаль: навигация и Обзор на английском", async ({ page }) => {
  await page.goto("/app/", { waitUntil: "domcontentloaded" });
  for (const label of ["Overview", "Models", "Runs", "Compare", "Policies", "Catalog", "Admin"]) {
    await expect(page.getByRole("link", { name: label, exact: true })).toBeVisible();
  }
  await expect(page.getByRole("heading", { name: "Needs attention" })).toBeVisible();
});

test("EN-локаль: Админ содержит поле URL судьи", async ({ page }) => {
  await page.goto("/app/admin", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Judge model" })).toBeVisible();
  await expect(page.getByText(/Judge engine URL/)).toBeVisible();
});
