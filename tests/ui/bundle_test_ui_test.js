#!/usr/bin/env node
/* U12 UI-тест: подзакладка «Тест bundle» — запуск теста (job инференса) из интерфейса.
 * Требует реального bundle с моделью в хранилище: MLSCAN_BUNDLE_ID (иначе SKIP). */
'use strict';
const fs = require('fs'), os = require('os'), path = require('path');
const puppeteer = require('puppeteer-core');
const BASE = process.env.MLSCAN_UI_URL || 'http://analytics.mlscan.local:30217';
const USER = process.env.MLSCAN_UI_USER || 'admin', PASS = process.env.MLSCAN_UI_PASS || 'Admin-MLScan-1';
const BID = process.env.MLSCAN_BUNDLE_ID || '';
function chrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const c = path.join(os.homedir(), '.cache', 'puppeteer', 'chrome');
  if (fs.existsSync(c)) for (const d of fs.readdirSync(c)) { const p = path.join(c, d, 'chrome-linux64', 'chrome'); if (fs.existsSync(p)) return p; }
  for (const p of ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome', '/snap/bin/chromium']) if (fs.existsSync(p)) return p;
  throw new Error('Chrome не найден');
}
(async () => {
  const fails = [];
  const browser = await puppeteer.launch({ executablePath: chrome(), headless: 'new',
    protocolTimeout: 600000, args: ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'] });
  const page = await browser.newPage();
  page.setDefaultTimeout(60000);
  page.on('pageerror', (e) => fails.push('JS: ' + String(e)));
  try {
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[name=username]');
    await page.type('input[name=username]', USER); await page.type('input[name=password]', PASS);
    await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.click('button[type=submit]')]);
    await page.waitForSelector('#downloads');
    await page.click('#downloads .tab[data-tab="tab-bundletest"]');
    await page.waitForSelector('#btbundle', { visible: true });
    const has = await page.$('#btbtn');
    if (!has) { fails.push('нет кнопки запуска теста bundle'); }
    if (!BID) {
      console.log('[ui-bundle] SKIP: MLSCAN_BUNDLE_ID не задан (нужен bundle с моделью в хранилище)');
      return;
    }
    await page.type('#btbundle', BID);
    await page.click('#btbtn');
    await page.waitForFunction(() => /тест запущен|ERR/.test((document.getElementById('btstatus') || {}).textContent || ''), { timeout: 120000 });
    const st = await page.$eval('#btstatus', (e) => e.textContent);
    if (/ERR/.test(st)) fails.push('запуск теста из UI: ' + st);
    else console.log('[ui-bundle] запуск из UI:', st);
  } catch (e) { fails.push(String(e && e.message ? e.message : e)); }
  finally { await browser.close(); }
  if (fails.length) { console.log('[ui-bundle] FAIL:'); fails.forEach((f) => console.log('   -', f)); process.exit(1); }
  console.log('[ui-bundle] OK');
})();
