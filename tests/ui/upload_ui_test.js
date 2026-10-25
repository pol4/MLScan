#!/usr/bin/env node
/* UI-тест (браузер) загрузки файла через веб-интерфейс MLScan (этап P0-1).
 *
 * Проверяет: вход в UI, доступность формы загрузки, загрузку файла через UI
 * и появление записи о скане; отсутствие ошибок JS в консоли.
 *
 * Переменные окружения:
 *   MLSCAN_UI_URL   (по умолчанию http://analytics.mlscan.local:30217)
 *   MLSCAN_UI_USER  (по умолчанию admin)
 *   MLSCAN_UI_PASS  (по умолчанию Admin-MLScan-1)
 *   CHROME_PATH     (путь к chrome; иначе ищется автоматически)
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const puppeteer = require('puppeteer-core');

const BASE = process.env.MLSCAN_UI_URL || 'http://analytics.mlscan.local:30217';
const USER = process.env.MLSCAN_UI_USER || 'admin';
const PASS = process.env.MLSCAN_UI_PASS || 'Admin-MLScan-1';

function findChrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const cache = path.join(os.homedir(), '.cache', 'puppeteer', 'chrome');
  if (fs.existsSync(cache)) {
    for (const d of fs.readdirSync(cache)) {
      const p = path.join(cache, d, 'chrome-linux64', 'chrome');
      if (fs.existsSync(p)) return p;
    }
  }
  for (const p of ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome', '/snap/bin/chromium']) {
    if (fs.existsSync(p)) return p;
  }
  throw new Error('Chrome не найден (задайте CHROME_PATH)');
}

(async () => {
  const fails = [];
  const errors = [];
  const browser = await puppeteer.launch({
    executablePath: findChrome(),
    headless: 'new',
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'],
  });
  const page = await browser.newPage();
  const bad = [];
  page.on('response', (r) => {
    const u = r.url();
    if (r.status() >= 400 && !/favicon\.ico$/.test(u)) bad.push(`${r.status()} ${u}`);
  });
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const t = m.text();
    // ресурсные 4xx относятся к странице login (проверка сессии до входа) — не JS-ошибка
    if (/Failed to load resource/.test(t)) return;
    errors.push(t);
  });
  page.on('pageerror', (e) => errors.push(String(e)));

  try {
    await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForSelector('input[name=username]', { timeout: 15000 });
    await page.type('input[name=username]', USER);
    await page.type('input[name=password]', PASS);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 30000 }),
      page.click('button[type=submit]'),
    ]);
    console.log('[ui] вход выполнен, url=', page.url());
    bad.length = 0;  // 4xx до входа (проверка сессии) не считаем ошибкой
    await page.waitForSelector("#f input[type=file]", { timeout: 15000 });
    console.log('[ui] форма загрузки доступна');

    const name = `uitest-${Date.now()}.pkl`;
    const tmp = path.join(os.tmpdir(), name);
    fs.writeFileSync(tmp, Buffer.alloc(256 * 1024, 7));
    const input = await page.$('#f input[type=file]');
    await input.uploadFile(tmp);
    await page.click('#f button[type=submit]');
    console.log('[ui] файл отправлен через UI:', name);

    await page.waitForFunction(
      (n) => document.body && document.body.innerText.includes(n),
      { timeout: 60000 }, name);
    console.log('[ui] запись о скане появилась в интерфейсе');
    fs.unlinkSync(tmp);
  } catch (e) {
    fails.push(String(e && e.message ? e.message : e));
  } finally {
    await browser.close();
  }

  if (errors.length) {
    console.log('[ui] ошибки JS в консоли:');
    errors.forEach((e) => console.log('   -', e));
    fails.push(...errors.map((e) => 'JS: ' + e));
  }
  if (bad.length) {
    console.log('[ui] неуспешные ответы после входа:');
    bad.forEach((b) => console.log('   -', b));
    fails.push(...bad.map((b) => 'HTTP ' + b));
  }
  if (fails.length) {
    console.log('[ui] FAIL:');
    fails.forEach((f) => console.log('   -', f));
    process.exit(1);
  }
  console.log('[ui] OK: UI-загрузка работает, ошибок JS нет');
})();
