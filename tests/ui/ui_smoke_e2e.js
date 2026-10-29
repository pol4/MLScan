#!/usr/bin/env node
/* UI E2E под актуальную структуру интерфейса MLScan (разделы Сканы/Загрузка/Настройки/Администрирование).
 *
 * Проверяет то, что реально важно оператору:
 *   1) вход (логин/пароль) и переход на дашборд;
 *   2) навигацию по разделам (кнопки .v3tab -> видимость #sec-*);
 *   3) «Сканы»: список артефактов, карточка артефакта (вердикт, находки, история, связи),
 *      ссылки отчётов (JSON/HTML) и запуск теста инференса из карточки (#v3test-btn);
 *   4) «Загрузка»: подзакладки (Модели/Локальные LLM/Движки/Модель с HF) и наличие движка из реестра;
 *   5) «Настройки» и «Администрирование»: ключевые панели на месте;
 *   6) API: CI-gate и целостность цепочки вердиктов.
 *
 * Запуск (пример для стенда без DNS-зоны на АРМ):
 *   MLSCAN_UI_URL=http://analytics.mlscan.local:31110 \
 *   MLSCAN_HOST_MAP=analytics.mlscan.local=192.168.20.116,s3.mlscan.local=192.168.20.116 \
 *   MLSCAN_API_KEY=<adm> MLSCAN_TESTING_URL=http://127.0.0.1:18080 \
 *   MLSCAN_ARTIFACT_SHA=<sha256 артефакта для карточки> node tests/ui/ui_smoke_e2e.js
 */
'use strict';
const fs = require('fs'), os = require('os'), path = require('path'), http = require('http');
const puppeteer = require('puppeteer-core');

const BASE = process.env.MLSCAN_UI_URL || 'http://analytics.mlscan.local:31110';
const USER = process.env.MLSCAN_UI_USER || 'admin';
const PASS = process.env.MLSCAN_UI_PASS || 'Admin-MLScan-1';
const API_KEY = process.env.MLSCAN_API_KEY || '';
const TESTING = process.env.MLSCAN_TESTING_URL || 'http://127.0.0.1:18080';
const SHA = process.env.MLSCAN_ARTIFACT_SHA || '';
const ENGINE_HINT = process.env.MLSCAN_ENGINE_HINT || 'mlscan/llama-cpp';

function chrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  for (const p of ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome', '/snap/bin/chromium'])
    if (fs.existsSync(p)) return p;
  const c = path.join(os.homedir(), '.cache', 'puppeteer', 'chrome');
  if (fs.existsSync(c)) for (const d of fs.readdirSync(c)) {
    const p = path.join(c, d, 'chrome-linux64', 'chrome'); if (fs.existsSync(p)) return p;
  }
  throw new Error('Chrome не найден (задайте CHROME_PATH)');
}
function tapi(p) {
  return new Promise((resolve) => {
    const u = new URL(TESTING + p);
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: 'GET', headers: { 'X-API-Key': API_KEY } }, (res) => {
      let d = ''; res.on('data', (c) => d += c);
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (e) {} resolve({ status: res.statusCode, json: j }); });
    });
    req.on('error', () => resolve({ status: 0, json: null })); req.end();
  });
}

(async () => {
  const fails = [];
  const ok = (m) => console.log('[ok]   ' + m);
  const bad = (m) => { fails.push(m); console.log('[FAIL] ' + m); };
  const hostMap = (process.env.MLSCAN_HOST_MAP || '').split(',').map(s => s.trim()).filter(Boolean)
    .map(pair => 'MAP ' + pair.split('=')[0] + ' ' + pair.split('=')[1]).join(',');
  const args = ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'];
  if (hostMap) args.push('--host-resolver-rules=' + hostMap);
  const browser = await puppeteer.launch({ executablePath: chrome(), headless: 'new',
    protocolTimeout: 1800000, args });
  const page = await browser.newPage();
  page.setDefaultTimeout(60000);
  page.on('pageerror', (e) => fails.push('JS: ' + String(e)));
  const httpErrors = [];
  page.on('response', (r) => { const u = r.url(); if (r.status() >= 400 && !/favicon/.test(u)) httpErrors.push(r.status() + ' ' + u); });

  try {
    console.log('== вход ' + BASE);
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[name=username]');
    await page.type('input[name=username]', USER);
    await page.type('input[name=password]', PASS);
    await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.click('button[type=submit]')]);
    await page.waitForSelector('#v3nav');
    httpErrors.length = 0;
    ok('вход выполнен: ' + page.url());

    console.log('== навигация по разделам');
    for (const [sec, id] of [['upload', 'sec-upload'], ['settings', 'sec-settings'], ['admin', 'sec-admin'], ['scans', 'sec-scans']]) {
      await page.click(`#v3nav .v3tab[data-v3="${sec}"]`);
      const visible = await page.$eval('#' + id, (e) => e.offsetParent !== null);
      if (visible) ok(`раздел «${sec}» открывается (${id})`); else bad(`раздел «${sec}» не отображается`);
    }

    console.log('== раздел «Сканы»: список артефактов и карточка');
    await page.waitForFunction(() => {
      const el = document.getElementById('v3artlist');
      return el && /v3art|нет|artifacts/i.test(el.innerHTML);
    }, { timeout: 60000 });
    const artCount = await page.$$eval('#v3artlist a.v3art', (els) => els.length);
    if (artCount > 0) ok(`в списке артефактов: ${artCount}`); else bad('список артефактов пуст');

    let sha = SHA;
    if (!sha && artCount > 0) sha = await page.$eval('#v3artlist a.v3art', (e) => e.dataset.sha);
    if (sha) {
      await page.evaluate((s) => {
        const a = document.querySelector(`#v3artlist a.v3art[data-sha="${s}"]`) ||
                  document.querySelector('#v3artlist a.v3art');
        a && a.click();
      }, sha);
      await page.waitForSelector('#v3artdetail', { visible: true, timeout: 60000 });
      // карточка наполняется асинхронно (запрос /v3/artifacts/<sha>) — ждём контент
      await page.waitForFunction(() => {
        const el = document.getElementById('v3artdetail');
        return el && /вердикт|Находки|ERR/i.test(el.textContent || '');
      }, { timeout: 60000, polling: 500 }).catch(() => {});
      const txt = await page.$eval('#v3artdetail', (e) => e.textContent || '');
      if (/вердикт/i.test(txt)) ok('карточка артефакта: показан вердикт'); else bad('карточка: нет вердикта');
      if (/Находки/i.test(txt)) ok('карточка: блок находок'); else bad('карточка: нет находок');
      if (/История тестов/i.test(txt)) ok('карточка: история тестов'); else bad('карточка: нет истории');
      const reportOk = await page.evaluate(async (s) => {
        const r = await fetch('/v3/artifacts/' + encodeURIComponent(s) + '/report.json', { cache: 'no-store' });
        if (!r.ok) return 'HTTP ' + r.status;
        const j = await r.json();
        return j && (j.verdict !== undefined || j.artifact) ? 'ok' : 'shape';
      }, sha);
      if (reportOk === 'ok') ok('отчёт JSON доступен'); else bad('отчёт JSON: ' + reportOk);

      console.log('== запуск теста инференса из карточки');
      // список движков подгружается отдельным запросом /images/list
      await page.waitForFunction(() => {
        const sel = document.getElementById('v3bind-engine');
        return sel && sel.options.length > 1;
      }, { timeout: 60000, polling: 500 }).catch(() => {});
      const engines = await page.$eval('#v3bind-engine', (e) => Array.from(e.options).map((o) => o.textContent));
      if (engines.some((t) => t.includes(ENGINE_HINT) || t.includes('llama'))) ok('в списке движков есть llama.cpp'); else bad('движок llama.cpp не найден в списке');
      const opt = engines.find((t) => t.includes(ENGINE_HINT) || t.includes('llama'));
      if (opt) {
        await page.select('#v3bind-engine', await page.$eval('#v3bind-engine', (e, needle) =>
          (Array.from(e.options).find((o) => o.textContent === needle) || {}).value, opt));
        await page.click('#v3test-btn');
        await page.waitForFunction(() => {
          const s = document.getElementById('v3bind-status');
          return s && /тест запущен|не запущен|ERR/.test(s.textContent || '');
        }, { timeout: 120000 });
        const st = await page.$eval('#v3bind-status', (e) => e.textContent);
        if (/тест запущен/.test(st)) ok('тест запущен: ' + st.slice(0, 90)); else bad('запуск теста: ' + st);
      }
    } else {
      bad('не удалось определить артефакт для карточки');
    }

    console.log('== раздел «Загрузка»: подзакладки и движки');
    await page.click('#v3nav .v3tab[data-v3="upload"]');
    await page.waitForSelector('#downloads', { visible: true });
    const tabs = await page.$$eval('#downloads .tab', (els) => els.map((e) => e.dataset.tab).filter(Boolean));
    for (const t of ['tab-models', 'tab-local', 'tab-engines', 'tab-hf']) {
      if (tabs.includes(t)) ok(`подзакладка ${t}`); else bad(`нет подзакладки ${t}`);
    }
    await page.click('#downloads .tab[data-tab="tab-engines"]');
    await page.waitForFunction(() => {
      const el = document.getElementById('enginelist') || document.getElementById('engines') || document.body;
      return /mlscan\/|digest|нет/i.test(el.textContent || '');
    }, { timeout: 30000 }).catch(() => bad('список движков не отрисован'));

    console.log('== раздел «Администрирование»');
    await page.click('#v3nav .v3tab[data-v3="admin"]');
    const adminTxt = await page.$eval('#sec-admin', (e) => e.textContent || '');
    for (const [needle, name] of [['квот', 'квоты'], ['журнал', 'журналы'], ['целостн', 'целостность цепочки']]) {
      if (new RegExp(needle, 'i').test(adminTxt)) ok(`админ-панель: ${name}`); else bad(`админ-панель: нет «${name}»`);
    }

    console.log('== API: gate и evidence');
    const gate = await tapi('/gate?image=' + encodeURIComponent('192.168.20.254:30003/mlscan/llama-cpp@sha256:d854233e9f043046f363953047ff518a9792b044cea1d53f86d299e88344cd5f') + '&model=sha256:0ef57d2c838458a1952664260dcba38e5bdda37494f3af732f06e4add24068e3');
    if (gate.json && gate.json.decision) ok('CI-gate: ' + gate.json.decision); else bad('CI-gate не ответил решением');
    const ev = await tapi('/v3/evidence/verify');
    if (ev.json && ev.json.ok) ok('evidence verify: ok, записей ' + ev.json.count); else bad('evidence verify не прошёл');

    const badHttp = httpErrors.filter((x) => !/40[13]/.test(x));
    if (badHttp.length) bad('HTTP-ошибки на странице: ' + badHttp.slice(0, 5).join(', '));
    else ok('на страницах нет неожиданных HTTP-ошибок');
  } catch (e) {
    bad('исключение: ' + String(e && e.message || e));
  } finally {
    await browser.close();
  }
  console.log(fails.length ? `\nИТОГ: провалов ${fails.length}` : '\nИТОГ: все проверки пройдены');
  process.exit(fails.length ? 1 : 0);
})();
