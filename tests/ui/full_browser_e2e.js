#!/usr/bin/env node
/* Полный браузерный E2E системы MLScan (несколько примеров, включая LLM):
 *   1) движки: импорт реального llama.cpp по digest через UI;
 *   2) HF-токен: сохранение и маскирование;
 *   3) локальная LLM: загрузка реального GGUF -> скан + bundle;
 *   4) ИНФЕРЕНС локальной LLM: «Тест bundle» -> job -> вердикт/аттестация;
 *   5) HF: реальный поиск + реальная загрузка LLM (Q8_0) -> bundle;
 *   6) ИНФЕРЕНС HF-модели: «Тест bundle» -> вердикт;
 *   7) не-LLM примеры: реальный safetensors -> вердикт; реальный архив (zip) -> вердикт;
 *   8) API-проверки: сенсор (sensor_events), CI-gate, цепочка вердиктов (/v3/evidence/verify).
 *
 * Требует: реальные фикстуры в /tmp (tests/e2e/make_fixtures.sh), HF-egress, свободный GPU (или CPU-движок).
 * Запуск: MLSCAN_API_KEY=<adm> MLSCAN_TESTING_URL=http://localhost:18080 node tests/ui/full_browser_e2e.js
 */
'use strict';
const fs = require('fs'), os = require('os'), path = require('path'), http = require('http'), crypto = require('crypto');
const { spawn } = require('child_process');
const puppeteer = require('puppeteer-core');

const BASE = process.env.MLSCAN_UI_URL || 'http://analytics.mlscan.local:30217';
const USER = process.env.MLSCAN_UI_USER || 'admin', PASS = process.env.MLSCAN_UI_PASS || 'Admin-MLScan-1';
const ENGINE_CUDA = 'sha256:1fa7f8f0ca663fdcf3203dc125a7e0b5c9e49c9ed054b049599666cd7e300eb0';
const ENGINE_CPU = 'sha256:b51c252687249a6990ae1c168156cb215c954bfd71f9c434eda9a065b1a40dbe';
const ENGINE_REF = process.env.MLSCAN_ENGINE_REF || 'ghcr.io/ggml-org/llama.cpp';
const HF_REPO = process.env.MLSCAN_HF_REPO || 'unsloth/gemma-3-270m-it-GGUF';
const HF_QUERY = process.env.MLSCAN_HF_QUERY || 'gemma-3-270m-it-GGUF';
const GGUF = process.env.MLSCAN_GGUF || '/tmp/gemma-3-270m-it-Q8_0.gguf';
const SAFETENSORS = process.env.MLSCAN_ST || '/tmp/real-model.safetensors';
const ARCHIVE = process.env.MLSCAN_ZIP || '/tmp/real-model-pack.zip';
const HF_WAIT_MS = +(process.env.MLSCAN_HF_WAIT_MS || 900000);
const TEST_WAIT_MS = +(process.env.MLSCAN_TEST_WAIT_MS || 900000);
const TESTING = process.env.MLSCAN_TESTING_URL || 'http://localhost:18080';
const API_KEY = process.env.MLSCAN_API_KEY || '';

function chrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const c = path.join(os.homedir(), '.cache', 'puppeteer', 'chrome');
  if (fs.existsSync(c)) for (const d of fs.readdirSync(c)) { const p = path.join(c, d, 'chrome-linux64', 'chrome'); if (fs.existsSync(p)) return p; }
  for (const p of ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome', '/snap/bin/chromium']) if (fs.existsSync(p)) return p;
  throw new Error('Chrome не найден');
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function tapi(p) {
  return new Promise((resolve) => {
    const u = new URL(TESTING + p);
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'GET',
      headers: { 'X-API-Key': API_KEY } }, (res) => {
      let d = ''; res.on('data', (c) => d += c);
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (e) {} resolve({ status: res.statusCode, json: j }); });
    });
    req.on('error', () => resolve({ status: 0, json: null })); req.end();
  });
}
const sha256 = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

let pf = null;                       // свой port-forward к сервису тестирования (API-проверки)
function startPortForward() {
  return new Promise((resolve) => {
    const u = new URL(TESTING);
    if (!/^(localhost|127\.0\.0\.1)$/.test(u.hostname)) return resolve();
    pf = spawn('kubectl', ['-n', 'mlscan-testing', 'port-forward', 'svc/mlscan-testing',
                           `${u.port || 18080}:8080`], { stdio: 'ignore' });
    let tries = 0;
    const t = setInterval(async () => {
      const h = await tapi('/healthz');
      if (h.status === 200 || ++tries > 30) { clearInterval(t); resolve(); }
    }, 1000);
  });
}
function stopPortForward() { if (pf) { try { pf.kill('SIGTERM'); } catch (e) {} pf = null; } }

(async () => {
  const fails = [], steps = [], bad = [];
  const step = (s) => { steps.push(s); console.log('[e2e] ' + s); };
  const browser = await puppeteer.launch({ executablePath: chrome(), headless: 'new',
    protocolTimeout: 3600000, args: ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'] });
  const page = await browser.newPage();
  page.setDefaultTimeout(90000);
  page.on('response', (r) => { const u = r.url(); if (r.status() >= 400 && !/favicon\.ico$/.test(u)) bad.push(r.status() + ' ' + u); });
  page.on('pageerror', (e) => fails.push('JS: ' + String(e)));

  // запуск «Теста bundle» в UI и ожидание вердикта
  async function runBundleTest(sha, label) {
    await page.click('#downloads .tab[data-tab="tab-bundletest"]');
    await page.waitForSelector('#btsha', { visible: true });
    await page.$eval('#btsha', (e) => { e.value = ''; });
    await page.$eval('#btbundle', (e) => { e.value = ''; });
    await page.type('#btsha', sha);
    await page.click('#btbtn');
    await page.waitForFunction(() => /тест запущен|ERR/.test((document.getElementById('btstatus') || {}).textContent || ''),
      { timeout: 120000 });
    const started = await page.$eval('#btstatus', (e) => e.textContent);
    if (/ERR/.test(started)) { fails.push(label + ': запуск теста: ' + started); return null; }
    step(label + ': ' + started);
    await page.waitForFunction(() => /тест завершён|тест не удался/.test((document.getElementById('btstatus') || {}).textContent || ''),
      { timeout: TEST_WAIT_MS, polling: 3000 });
    const st = await page.$eval('#btstatus', (e) => e.textContent);
    if (/не удался/.test(st)) fails.push(label + ': ' + st); else step(label + ': ' + st);
    return st;
  }

  try {
    if (!API_KEY) { console.log('[e2e] SKIP: MLSCAN_API_KEY не задан'); process.exit(0); }
    await startPortForward();

    // 1) вход
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[name=username]');
    await page.type('input[name=username]', USER); await page.type('input[name=password]', PASS);
    await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.click('button[type=submit]')]);
    bad.length = 0;
    await page.waitForSelector('#downloads');
    step('вход выполнен: ' + page.url());

    // 2) движки: импорт реального llama.cpp по digest через UI
    await page.click('#downloads .tab[data-tab="tab-engines"]');
    await page.waitForSelector('#imgref');
    for (const d of [ENGINE_CUDA, ENGINE_CPU]) {
      await page.$eval('#imgref', (e, v) => { e.value = v; }, `${ENGINE_REF}@${d}`);
      await page.click('#imgimport-btn');
      await page.waitForFunction(() => /registered|уже/.test((document.getElementById('imgstatus') || {}).textContent || ''), { timeout: 120000 });
    }
    const engines = await page.$$eval('#englist option', (o) => o.map((e) => e.value));
    step('движки: импортированы CUDA и CPU (в списке ' + engines.length + ')');
    if (!engines.includes(ENGINE_CPU)) fails.push('CPU-движок не появился в списке');

    // 3) HF-токен
    await page.click('#downloads .tab[data-tab="tab-hf"]');
    await page.waitForSelector('#hftoken');
    await page.type('#hftoken', 'hf_e2e_token_4321');
    await page.click('#hftokensave');
    await page.waitForFunction(() => /saved hf_\*\*\*/.test((document.getElementById('hftokenstatus') || {}).textContent || ''));
    step('HF-токен сохранён и замаскирован: ' + await page.$eval('#hftokenstatus', (e) => e.textContent));

    // 4) локальная LLM: реальный GGUF -> скан + bundle
    const ggufSha = sha256(GGUF);
    await page.click('#downloads .tab[data-tab="tab-local"]');
    await page.waitForSelector('#locengine');
    await page.select('#locengine', ENGINE_CPU);
    await (await page.$('#locfile')).uploadFile(GGUF);
    await page.click('#locbtn');
    await page.waitForFunction(() => /bundle b-|ERR/.test((document.getElementById('locstatus') || {}).textContent || ''),
      { timeout: 900000, polling: 1000 });
    const locSt = await page.$eval('#locstatus', (e) => e.textContent);
    if (/ERR/.test(locSt)) fails.push('локальная LLM: ' + locSt); else step('локальная LLM (реальный GGUF ' + (fs.statSync(GGUF).size / 1048576).toFixed(0) + ' МБ): ' + locSt);

    // 5) ИНФЕРЕНС локальной LLM (CPU-движок, Kata)
    let st = await runBundleTest(ggufSha, 'инференс локальной LLM');
    const apiTest = await tapi('/bundles?model=' + ggufSha);
    const bundlesLocal = (apiTest.json && apiTest.json.bundles) || [];

    // 6) HF: реальный поиск и загрузка LLM
    await page.click('#downloads .tab[data-tab="tab-hf"]');
    await page.$eval('#hfquery', (e, v) => { e.value = v; }, HF_QUERY);
    await page.type('#hftype', 'text-generation');
    await page.select('#hfquant', 'Q8_0');
    await page.select('#hfengine', ENGINE_CPU);
    await page.click('#hfsearch-btn');
    await page.waitForFunction(() => { const e = document.getElementById('hfresults'); return e && e.textContent.trim().length > 10; }, { timeout: 60000 });
    const results = await page.$$eval('#hfresults button[data-repo]', (bs) => bs.map((b) => b.dataset.repo));
    step('HF-поиск (реальный API): результатов ' + results.length + ', пример: ' + results.slice(0, 2).join(', '));
    const target = results.find((r) => r === HF_REPO) || results.find((r) => /gemma-3-270m-it-GGUF/i.test(r));
    if (!target) { fails.push('в выдаче HF нет ' + HF_REPO); }
    else {
      await page.$$eval('#hfresults button[data-repo]', (bs, t) => { const b = bs.find((x) => x.dataset.repo === t); b.click(); }, target);
      const t0 = Date.now();
      await page.waitForFunction(() => /done/.test((document.getElementById('hfstatus') || {}).textContent || ''),
        { timeout: HF_WAIT_MS, polling: 2000 });
      step('HF-загрузка завершена за ' + Math.round((Date.now() - t0) / 1000) + 'с: ' + await page.$eval('#hfstatus', (e) => e.textContent));
      const dls = await tapi('/hf/downloads');
      const tbase = String(target).split(':')[0];
      const dl = ((dls.json && dls.json.downloads) || []).find(
        (d) => (d.repo_id === target || d.repo_id === tbase || String(target).startsWith(d.repo_id)) && d.status === 'done');
      if (!dl) fails.push('нет done-загрузки для ' + target);
      else {
        step('HF-модель: sha=' + String(dl.model_sha256).slice(0, 12) + '…, bundle=' + (dl.bundle_id || '—'));
        if (dl.bundle_id && dl.model_sha256) {
          // 7) ИНФЕРЕНС HF-модели
          st = await runBundleTest(dl.model_sha256, 'инференс HF-модели');
          const ev = await tapi('/llm/events/' + (dl.bundle_id ? 'bundle-test-' + dl.bundle_id.slice(0, 16) : ''));
          const ids = ((ev.json && ev.json.findings) || []).map((f) => f.check_id);
          step('сенсор HF-инференса: findings=' + JSON.stringify([...new Set(ids)]));
        }
      }
    }

    // 8) не-LLM примеры: safetensors и архив
    for (const [file, label] of [[SAFETENSORS, 'safetensors-модель'], [ARCHIVE, 'архив (zip)']]) {
      if (!fs.existsSync(file)) { fails.push('нет файла ' + file); continue; }
      await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
      await page.waitForSelector('#f input[type=file]', { visible: true, timeout: 60000 });
      const nm = path.basename(file).replace(/^/, 'e2e-').replace(/(\.\w+)$/, '-' + Date.now() + '$1');
      const tmp = path.join('/tmp', nm); fs.copyFileSync(file, tmp);
      await (await page.$('#f input[type=file]')).uploadFile(tmp);
      await page.click('#f button[type=submit]');
      try {
        await page.waitForFunction((n) => document.body.innerText.includes(n), { timeout: 240000, polling: 2000 }, nm);
      } catch (e) {
        const snip = await page.evaluate(() => document.body.innerText.slice(0, 300));
        fails.push('не появилась строка загрузки ' + nm + ' (фрагмент страницы: ' + snip.replace(/\n+/g, ' | ').slice(0, 200) + ')');
        continue;
      }
      const sc = await tapi('/scans');
      const rec = ((sc.json && sc.json.scans) || []).find((s) => s.name === nm);
      let verdict = '—';
      if (rec) for (let i = 0; i < 80; i++) {
        const r = await tapi('/scans/' + rec.scan_id);
        if (r.json && ['done', 'error'].includes(r.json.state)) { verdict = r.json.verdict || '—'; break; }
        await sleep(3000);
      }
      step(label + ' (' + (fs.statSync(file).size / 1024).toFixed(0) + ' КБ): вердикт ' + verdict);
      fs.unlinkSync(tmp);
    }

    // 9) API: CI-gate и цепочка вердиктов
    const g = await tapi('/gate?image=' + encodeURIComponent(ENGINE_REF + '@' + ENGINE_CPU) + '&model=' + ggufSha);
    step('CI-gate: decision=' + (g.json && g.json.decision) + ', source=' + (g.json && g.json.source));
    if (!g.json || !g.json.decision) fails.push('CI-gate не вернул decision');
    const ch = await tapi('/v3/evidence/verify');
    step('цепочка вердиктов: ok=' + (ch.json && ch.json.ok) + ', звеньев=' + (ch.json && ch.json.count));
    if (!ch.json || !ch.json.ok) fails.push('цепочка вердиктов не прошла проверку');
  } catch (e) {
    fails.push(String(e && e.message ? e.message : e));
  } finally {
    stopPortForward();
    await browser.close();
  }
  if (bad.length) { console.log('[e2e] HTTP>=400 после входа:'); bad.slice(0, 8).forEach((b) => console.log('   -', b)); }
  if (fails.length) { console.log('[e2e] FAIL:'); fails.forEach((f) => console.log('   -', f)); process.exit(1); }
  console.log('[e2e] OK: полный браузерный прогон (несколько примеров, включая LLM и HF) — ' + steps.length + ' шагов');
})();
