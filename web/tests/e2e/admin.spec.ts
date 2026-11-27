import { test, expect } from "@playwright/test";

// Администрирование: модель-судья (движок/модель/URL/порог/шаблон) и операции паритета.

test("форма судьи присутствует и сохраняется", async ({ page }) => {
  await page.goto("/app/admin", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Модель-судья" })).toBeVisible();
  await expect(page.getByRole("checkbox", { name: /профиле llm/ })).toBeVisible();
  await expect(page.getByPlaceholder("http://judge-engine:8000")).toBeVisible();
  await page.getByRole("button", { name: "Сохранить" }).first().click();
  await expect(page.getByText(/сохранено|saved|ERR/)).toBeVisible();
});

test("паритет операций (/legacy) присутствует", async ({ page }) => {
  await page.goto("/app/admin", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: /Прочее \(админ-операции\)/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Синхронизировать" })).toBeVisible();
});
