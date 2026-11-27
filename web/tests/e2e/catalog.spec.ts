import { test, expect } from "@playwright/test";

// Каталог: движки/пакеты/датасеты/наборы вопросов (регресс фикса «Наборы вопросов»).

test("разделы каталога отображаются", async ({ page }) => {
  await page.goto("/app/catalog", { waitUntil: "domcontentloaded" });
  for (const h of ["Движки", "Пакеты тестов", "Датасеты", "Наборы вопросов"]) {
    await expect(page.getByRole("heading", { name: h })).toBeVisible();
  }
});

test("наборы вопросов: активный набор виден (не пусто)", async ({ page }) => {
  await page.goto("/app/catalog", { waitUntil: "domcontentloaded" });
  // фикс п.2: analytics отдаёт активный набор объектом {version,...} — карточка «Наборы вопросов»
  // должна показать строку набора, а не пустой список; импорт XLSX — рядом (label)
  await expect(page.getByRole("heading", { name: "Наборы вопросов" })).toBeVisible();
  await expect(page.getByText("Импорт XLSX")).toBeVisible();
  await expect(page.locator("table tr").first()).toBeVisible();
});
