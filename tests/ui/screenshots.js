#!/usr/bin/env node
/* Снимки экранов UI MLScan (актуальный тенант) через puppeteer-core.
 *
 * Аутентификация: сервис analytics доверяет заголовкам oauth2-proxy
 * (X-Forwarded-User / X-Forwarded-Groups) при MLSCAN_TRUST_PROXY=1, поэтому
 * снимки можно делать напрямую по port-forward к analytics, без Keycloak.
 *
 * Запуск:
 *   MLSCAN_UI_URL=http://127.0.0.1:18081 node tests/ui/screenshots.js
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const puppeteer = require('puppeteer-core');

const BASE = process.env.MLSCAN_UI_URL || 'http://127.0.0.1:18081';
const USER = process.env.MLSCAN_UI_USER || 'platformadmin';
const GROUPS = process.env.MLSCAN_UI_GROUPS || 'mlscan-admins';
const OUT = process.env.MLSCAN_SHOT_DIR || path.join(__dirname, '..', '..', 'docs', 'img', 'ui-e2e');

function chrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  for (const p of ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome', '/snap/bin/chromium'])
    if (fs.existsSync(p)) return p;
  const c = path.join(os.homedir(), '.cache', 'puppeteer', 'chrome');
  if (fs.existsSync(c)) for (const d of fs.readdirSync(c)) {
    const p = path.join(c, d, 'chrome-linux64', 'chrome');
    if (fs.existsSync(p)) return p;
  }
  throw new Error('Chrome не найден (задайте CHROME_PATH)');
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const base = new URL(BASE);
  const browser = await puppeteer.launch({
    executablePath: chrome(),
    headless: 'new',
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--window-size=1680,1050',
           '--force-device-scale-factor=1', '--lang=ru-RU'],
    defaultViewport: { width: 1680, height: 1050 },
  });
  const page = await browser.newPage();
  await page.setExtraHTTPHeaders({ 'X-Forwarded-User': USER, 'X-Forwarded-Groups': GROUPS });
  page.setDefaultNavigationTimeout(60000);

  const shot = async (name) => {
    const f = path.join(OUT, name + '.png');
    await page.screenshot({ path: f, fullPage: false });
    console.log('[shot]', f);
  };

  console.log('[ui] открываю', BASE);
  await page.goto(base.origin + '/', { waitUntil: 'networkidle2', timeout: 60000 });
  await page.waitForSelector('.v3tab', { timeout: 30000 });
  await sleep(1500);

  // 1. Сканы (стартовый экран)
  await page.evaluate(() => { const b = document.querySelector(".v3tab[data-v3='scans']"); if (b) b.click(); });
  await sleep(2000);
  await shot('01-scans');

  // 2. Карточка артефакта (первая ссылка в списке сканов)
  const card = await page.evaluate(() => {
    const a = document.querySelector("#sec-scans a.v3art");
    if (!a) return false;
    a.click();
    return true;
  });
  if (card) {
    try { await page.waitForFunction(() => {
      const d = document.getElementById('v3artdetail');
      return d && d.style.display !== 'none' && d.textContent && d.textContent.indexOf('загрузка') === -1;
    }, { timeout: 20000 }); } catch (e) {}
    await sleep(2500);
    await shot('02-artifact-card');
    // вернуться к списку сканов
    await page.evaluate(() => {
      const b = document.getElementById('v3d-back');
      if (b) b.click();
    });
    await sleep(1500);
    await page.evaluate(() => { const b = document.querySelector(".v3tab[data-v3='scans']"); if (b) b.click(); });
    await sleep(1000);
  }

  // 3. Загрузка (подзакладки)
  await page.evaluate(() => { const b = document.querySelector(".v3tab[data-v3='upload']"); if (b) b.click(); });
  await sleep(2000);
  await shot('03-upload-models');
  for (const [tab, name] of [['tab-bundletest', '04-upload-bundletest'],
                             ['tab-engines', '05-upload-engines'],
                             ['tab-hf', '06-upload-hf']]) {
    const ok = await page.evaluate((t) => {
      const b = document.querySelector(`#downloads .tab[data-tab='${t}'], .tab[data-tab='${t}']`);
      if (b) { b.click(); return true; }
      return false;
    }, tab);
    if (ok) { await sleep(1500); await shot(name); }
  }

  // 4. История операций
  await page.evaluate(() => { const b = document.querySelector(".v3tab[data-v3='ops']"); if (b) b.click(); });
  await sleep(1800);
  await shot('07-operations');

  // 5. Настройки
  await page.evaluate(() => { const b = document.querySelector(".v3tab[data-v3='settings']"); if (b) b.click(); });
  await sleep(1800);
  await shot('08-settings');

  // 6. Администрирование
  await page.evaluate(() => { const b = document.querySelector('#v3admin-tab, .v3tab[data-v3=admin]'); if (b) b.click(); });
  await sleep(1800);
  await shot('09-admin');

  await browser.close();
  console.log('[ui] готово, снимки в', OUT);
})().catch((e) => { console.error('[ui] ошибка:', e.message); process.exit(1); });
