import { test, expect } from "@playwright/test";

// Проверки (Runs): фильтры, «только риск/сбои», сохранение вида, выбор для сравнения.

const KIND = 'select:has(option[value="bundle"])';

test("фильтры и сброс", async ({ page }) => {
  await page.goto("/app/runs", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Проверки" })).toBeVisible();
  const kind = page.locator(KIND).first();
  await kind.selectOption("bundle");
  await expect(kind).toHaveValue("bundle");
  await page.getByRole("button", { name: "Сброс" }).click();
  await expect(kind).toHaveValue("");
});

test("сохранить вид (prompt) и «только риск/сбои»", async ({ page }) => {
  await page.goto("/app/runs", { waitUntil: "domcontentloaded" });
  page.once("dialog", (d) => d.accept("e2e/view"));
  await page.getByRole("button", { name: "Сохранить вид" }).click();
  const cb = page.getByRole("checkbox").first();
  await cb.check();
  await expect(cb).toBeChecked();
});

test("выбор прогонов для сравнения ведёт в «Сравнение»", async ({ page }) => {
  await page.goto("/app/runs", { waitUntil: "domcontentloaded" });
  const boxes = page.getByRole("checkbox");
  if ((await boxes.count()) > 1) {
    await boxes.nth(1).check();
    await page.getByRole("button", { name: /Сравнить/ }).click();
    await expect(page).toHaveURL(/\/app\/compare/);
    await expect(page.getByRole("heading", { name: /Сравнение прогонов/ })).toBeVisible();
  }
});
