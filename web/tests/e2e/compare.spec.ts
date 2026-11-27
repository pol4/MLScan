import { test, expect } from "@playwright/test";

// Сравнение прогонов и тренды (по прямым ссылкам на известные bundle).

const RUN = process.env.E2E_RUN || "b-6ab839753931fa5c1ca89aa4";
const RUN2 = process.env.E2E_RUN2 || "b-3b36b17301e676b5473f2fe6";

test("страница сравнения: заголовок и тренды", async ({ page }) => {
  await page.goto(`/app/compare?ids=${RUN},${RUN2}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: /Сравнение прогонов/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: /Тренды/ })).toBeVisible();
});

test("сравнение без выбранных прогонов показывает подсказку", async ({ page }) => {
  await page.goto("/app/compare", { waitUntil: "domcontentloaded" });
  await expect(page.getByText(/Выберите прогоны|Pick runs/)).toBeVisible();
});
