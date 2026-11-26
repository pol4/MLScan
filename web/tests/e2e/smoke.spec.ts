import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const NAV = ["Обзор", "Модели", "Проверки", "Сравнение", "Находки", "Политики", "Каталог", "Гейт", "Администрирование"];

test("навигация отображается", async ({ page }) => {
  await page.goto("/app/");
  for (const label of NAV) {
    await expect(page.getByRole("link", { name: label, exact: true })).toBeVisible();
  }
});

test("Обзор загружается (KPI + 'требует внимания')", async ({ page }) => {
  await page.goto("/app/");
  await expect(page.getByRole("heading", { name: "Требует внимания" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Последние прогоны" })).toBeVisible();
});

test("Проверки: список и переход в карточку", async ({ page }) => {
  await page.goto("/app/runs");
  await expect(page.getByRole("heading", { name: "Проверки" })).toBeVisible();
  const open = page.getByRole("link", { name: "Открыть" }).first();
  if (await open.count()) {
    await open.click();
    await expect(page.getByRole("button", { name: "Сводка" })).toBeVisible();
  }
});

test("Каталог загружается", async ({ page }) => {
  await page.goto("/app/catalog");
  await expect(page.getByRole("heading", { name: "Движки" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Пакеты тестов" })).toBeVisible();
});

test("a11y: нет critical/serious нарушений на Обзоре", async ({ page }) => {
  await page.goto("/app/");
  const res = await new AxeBuilder({ page }).analyze();
  const bad = res.violations.filter((v) => ["critical", "serious"].includes(v.impact || ""));
  expect(bad.map((v) => v.id)).toEqual([]);
});
