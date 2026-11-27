import { test, expect } from "@playwright/test";

// Карточка прогона: вкладки, кейсы, доказательства.

async function openFirstRun(page: any): Promise<boolean> {
  await page.goto("/app/runs", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Проверки" })).toBeVisible();
  const open = page.getByRole("link", { name: "Открыть" }).first();
  const ok = await open.waitFor({ state: "visible", timeout: 20000 }).then(() => true).catch(() => false);
  if (ok) await open.click();
  return ok;
}

test("вкладки карточки прогона", async ({ page }) => {
  test.skip(!(await openFirstRun(page)), "нет прогонов для открытия");
  await expect(page.getByRole("button", { name: "Сводка" })).toBeVisible();
  for (const tab of ["Кейсы", "Наблюдение", "Доказательства"]) {
    await expect(page.getByRole("button", { name: tab })).toBeVisible();
  }
});

test("вкладка «Доказательства» показывает digest", async ({ page }) => {
  test.skip(!(await openFirstRun(page)), "нет прогонов");
  await page.getByRole("button", { name: "Доказательства" }).click();
  await expect(page.locator("code").first()).toBeVisible();
});

test("вкладка «Кейсы»: фильтр «только не пройденные»", async ({ page }) => {
  test.skip(!(await openFirstRun(page)), "нет прогонов");
  await page.getByRole("button", { name: "Кейсы" }).click();
  const onlyFailed = page.getByRole("checkbox").last();
  await onlyFailed.check();
  await expect(onlyFailed).toBeChecked();
});
