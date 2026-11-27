// Съёмка скриншотов нового UI (/app) с реального стенда через BFF (analytics).
// Запуск: node scripts/capture-ui.mjs [baseURL]
// Аутентификация — заголовками oauth2-proxy (как в e2e): X-Forwarded-User/Groups.
// ВНИМАНИЕ: кадры с боевого тенанта содержат операционные данные — проверяйте/обезличивайте перед коммитом;
// для черновых съёмок задавайте git-игнорируемый SHOT_DIR.
import { chromium } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

const BASE = (process.argv[2] || process.env.E2E_BASE_URL || "http://127.0.0.1:18080").replace(/\/$/, "");
const LANG = process.env.SHOT_LANG || "ru";              // ru | en (UI хранит язык в localStorage.mlscan_lang)
const OUT = process.env.SHOT_DIR || path.resolve(process.cwd(), "..", "docs", "img", "ui-v4", ...(LANG === "en" ? ["en"] : []));
fs.mkdirSync(OUT, { recursive: true });

const RUN_ID = process.env.SHOT_RUN || "b-6ab839753931fa5c1ca89aa4";
const RUN_ID2 = process.env.SHOT_RUN2 || "b-3b36b17301e676b5473f2fe6";

const PAGES = [
  ["01-overview", "/app/"],
  ["02-models", "/app/models"],
  ["03-runs", "/app/runs"],
  ["04-run-detail", `/app/runs/${encodeURIComponent(RUN_ID)}?kind=bundle`],
  ["05-compare", `/app/compare?ids=${encodeURIComponent(RUN_ID)},${encodeURIComponent(RUN_ID2)}`],
  ["06-policies", "/app/policies"],
  ["07-catalog", "/app/catalog"],
  ["08-onboarding", "/app/onboarding"],
  ["09-admin", "/app/admin"],
];

const browser = await chromium.launch();
const ctx = await browser.newContext({
  viewport: { width: 1512, height: 900 },
  deviceScaleFactor: Number(process.env.SHOT_DSF || 1),
  locale: LANG === "en" ? "en-US" : "ru-RU",
  ignoreHTTPSErrors: true,
  extraHTTPHeaders: {
    "X-Forwarded-User": process.env.E2E_USER || "admin",
    "X-Forwarded-Groups": process.env.E2E_GROUPS || "mlscan-admins",
    "X-Forwarded-Email": "admin@platform.rtx.local",
  },
});
const page = await ctx.newPage();
// Зафиксировать язык интерфейса (localStorage.mlscan_lang) до первой отрисовки.
await ctx.addInitScript((l) => { try { localStorage.setItem("mlscan_lang", l); } catch {} }, LANG);

let failed = 0;
for (const [name, url] of PAGES) {
  try {
    await page.goto(BASE + url, { waitUntil: "networkidle", timeout: 30000 });
  } catch { /* networkidle может не наступить (SSE) — игнорируем */ }
  await page.waitForTimeout(1500);
  const file = path.join(OUT, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  const title = (await page.title().catch(() => "")) || "";
  console.log(`saved ${path.relative(process.cwd(), file)}  ${title}`);
}

await browser.close();
process.exit(failed ? 1 : 0);
