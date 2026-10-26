#!/usr/bin/env node
/* Полный браузерный E2E по инструкции оператора (Arch_v3/20-operator-guide.md) с РЕАЛЬНЫМИ моделями.
 * Сценарии: движки (реальные digest), HF-токен, S2 (реальный поиск/загрузка LLM с HF + bundle),
 * S2-локально (реальный GGUF → скан + bundle), S4 (перепривязка на другой реальный движок),
 * S1 (реальная не-LLM модель safetensors), S3 (реальный архив), S5 (CI-gate через API).
 * Требует: puppeteer-core, реальные файлы в /tmp (см. переменные ниже), доступ к UI и HF-egress.
 */
'use strict';
const fs = require('fs'), os = require('os'), path = require('path'), http = require('http');
const puppeteer = require('puppeteer-core');

const BASE = process.env.MLSCAN_UI_URL || 'http://analytics.mlscan.local:30217';
const USER = process.env.MLSCAN_UI_USER || 'admin', PASS = process.env.MLSCAN_UI_PASS || 'Admin-MLScan-1';
const ENGINE_CUDA = 'sha256:1fa7f8f0ca663fdcf3203dc125a7e0b5c9e49c9ed054b049599666cd7e300eb0';
const ENGINE_CPU = 'sha256:b51c252687249a6990ae1c168156cb215c954bfd71f9c434eda9a065b1a40dbe';
const HF_REPO = process.env.MLSCAN_HF_REPO || 'unsloth/gemma-3-270m-it-GGUF';
const HF_QUERY = process.env.MLSCAN_HF_QUERY || 'gemma-3-270m-it-GGUF';
const GGUF = process.env.MLSCAN_GGUF || '/tmp/gemma-3-270m-it-Q8_0.gguf';
const SAFETENSORS = process.env.MLSCAN_ST || '/tmp/real-model.safetensors';
const ARCHIVE = process.env.MLSCAN_ZIP || '/tmp/real-model-pack.zip';
const HF_WAIT_MS = +(process.env.MLSCAN_HF_WAIT_MS || 900000);
const TESTING = process.env.MLSCAN_TESTING_URL || 'http://localhost:18080';
const API_KEY = process.env.MLSCAN_API_KEY || 'adm_6632cd8b4ea7b93c';

/* Прямой вызов API сервиса тестирования (для проверок вне UI). */
function tapi(p) {
  return new Promise((resolve) => {
    const u = new URL(TESTING + p);
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: 'GET', headers: { 'X-API-Key': API_KEY } }, (res) => {
      let d = ''; res.on('data', (c) => d += c);
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (e) {}
        resolve({ status: res.statusCode, json: j }); });
    });
    req.on('error', () => resolve({ status: 0, json: null }));
    req.end();
  });
}

function chrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const c = path.join(os.homedir(), '.cache', 'puppeteer', 'chrome');
  if (fs.existsSync(c)) for (const d of fs.readdirSync(c)) { const p = path.join(c, d, 'chrome-linux64', 'chrome'); if (fs.existsSync(p)) return p; }
  for (const p of ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome', '/snap/bin/chromium']) if (fs.existsSync(p)) return p;
  throw new Error('Chrome не найден');
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const fails = [], steps = [];
  const step = (s) => { steps.push(s); console.log('[e2e] ' + s); };
  const bad = [];
  const browser = await puppeteer.launch({ executablePath: chrome(), headless: 'new',
    protocolTimeout: 3600000,
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'] });
  const page = await browser.newPage();
  page.setDefaultTimeout(60000);
  page.on('response', (r) => { const u = r.url();
    if (r.status() >= 400 && !/favicon\.ico$/.test(u)) bad.push(r.status() + ' ' + u); });
  page.on('pageerror', (e) => fails.push('JS: ' + String(e)));

  const apiUnused = (p, opts) => page.evaluate(async (p, opts) => {
    const r = await fetch(p, Object.assign({ cache: 'no-store' }, opts || {}));
    let j = null; try { j = await r.json(); } catch (e) {}
    return { status: r.status, json: j };
  }, p, opts);

  try {
    // ---------- вход ----------
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[name=username]');
    await page.type('input[name=username]', USER); await page.type('input[name=password]', PASS);
    await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.click('button[type=submit]')]);
    bad.length = 0;
    await page.waitForSelector('#downloads');
    step('вход выполнен: ' + page.url());

    // ---------- S2.1 движки: реальные digest ----------
    await page.click('#downloads .tab[data-tab="tab-engines"]');
    await page.waitForFunction(() => { const s = document.getElementById('englist'); return s && s.options.length > 1; });
    const engVals = await page.$$eval('#englist option', (o) => o.map((e) => e.value));
    for (const d of [ENGINE_CUDA, ENGINE_CPU]) if (!engVals.includes(d)) fails.push('движок не найден в списке: ' + d);
    step('движки: ' + engVals.filter(Boolean).length + ' шт., реальные digest присутствуют');

    // ---------- HF-токен ----------
    await page.click('#downloads .tab[data-tab="tab-hf"]');
    await page.waitForSelector('#hftoken');
    await page.type('#hftoken', 'hf_test_token_e2e_1234');
    await page.click('#hftokensave');
    await page.waitForFunction(() => /saved hf_\*\*\*/.test((document.getElementById('hftokenstatus') || {}).textContent || ''));
    step('HF-токен сохранён и замаскирован: ' + await page.$eval('#hftokenstatus', (e) => e.textContent));

    // ---------- S2: реальный поиск на HF ----------
    await page.type('#hfquery', HF_QUERY);
    await page.type('#hftype', 'text-generation');
    await page.select('#hfquant', 'Q8_0');
    await page.select('#hfengine', ENGINE_CUDA);
    await page.click('#hfsearch-btn');
    await page.waitForFunction((q) => {
      const e = document.getElementById('hfresults'); return e && e.textContent && e.textContent.length > 20;
    }, { timeout: 60000 }, HF_QUERY);
    const results = await page.$$eval('#hfresults button[data-repo]', (bs) => bs.map((b) => b.dataset.repo));
    step('HF-поиск (реальный API): результатов ' + results.length + ', пример: ' + results.slice(0, 3).join(', '));
    if (!results.length) fails.push('HF-поиск вернул пусто (реальный HF недоступен?)');
    const target = results.find((r) => r === HF_REPO) || results.find((r) => /gemma-3-270m-it-GGUF/i.test(r));
    if (!target) fails.push('в реальной выдаче HF нет ' + HF_REPO);

    // ---------- S2: реальная загрузка LLM + bundle ----------
    if (target) {
      await page.$$eval('#hfresults button[data-repo]', (bs, t) => {
        const b = bs.find((x) => x.dataset.repo === t); b.click();
      }, target);
      const t0 = Date.now();
      await page.waitForFunction(() => /done/.test((document.getElementById('hfstatus') || {}).textContent || ''),
        { timeout: HF_WAIT_MS, polling: 2000 });
      const st = await page.$eval('#hfstatus', (e) => e.textContent);
      const secs = Math.round((Date.now() - t0) / 1000);
      step('реальная загрузка с HF завершена за ' + secs + 'с: ' + st);
      const mb = (st.match(/(\d+)\/(\d+)/) || [])[2];
      if (mb && +mb < 1e6) fails.push('загружено подозрительно мало байт: ' + st);
      // проверяем sha/bundle реальной загрузки через API
      const dls = await tapi('/hf/downloads');
      const last = (dls.json && dls.json.downloads || []).find((d) => d.repo_id === target && d.status === 'done');
      if (!last) fails.push('нет done-загрузки для ' + target);
      else {
        if (!last.model_sha256 || !/^[0-9a-f]{64}$/.test(last.model_sha256)) fails.push('нет sha256 у HF-загрузки');
        if (!last.bundle_id) fails.push('bundle не создан при HF-загрузке с движком');
        else step('bundle для реальной HF-модели: ' + last.bundle_id + ' (model ' + String(last.model_sha256).slice(0, 12) + '…)');
      }
    }

    // ---------- S2-локально: реальный GGUF → скан + bundle ----------
    let ggufSha = null;
    if (fs.existsSync(GGUF)) {
      const crypto = require('crypto');
      ggufSha = crypto.createHash('sha256').update(fs.readFileSync(GGUF)).digest('hex');
      await page.click('#downloads .tab[data-tab="tab-local"]');
      await page.waitForSelector('#locengine');
      await page.select('#locengine', ENGINE_CPU);
      const inp = await page.$('#locfile'); await inp.uploadFile(GGUF);
      await page.click('#locbtn');
      await page.waitForFunction(() => /bundle b-|ERR/.test((document.getElementById('locstatus') || {}).textContent || ''),
        { timeout: 600000, polling: 1000 });
      const lstat = await page.$eval('#locstatus', (e) => e.textContent);
      if (/ERR/.test(lstat)) fails.push('локальная LLM-загрузка: ' + lstat);
      else step('реальный GGUF загружен через UI → ' + lstat);
      if (/ERR/.test(lstat) === false && ggufSha) {
        const b = await tapi('/bundles?model=' + ggufSha);
        const nb = (b.json && b.json.bundles || []).length;
        if (!nb) fails.push('нет bundle для sha загруженного GGUF (' + ggufSha.slice(0, 12) + '…)');
        else step('bundle для реального GGUF найден: ' + nb + ' шт.');
      }
    } else fails.push('нет файла GGUF: ' + GGUF);

    // ---------- S4: перепривязка на другой реальный движок ----------
    if (ggufSha) {
      await page.click('#downloads .tab[data-tab="tab-local"]');
      await page.waitForSelector('#rbsha');
      const before = await tapi('/bundles?model=' + ggufSha);
      const beforeIds = (before.json && before.json.bundles || []).map((x) => x.bundle_id);
      await page.type('#rbsha', ggufSha);
      await page.select('#rbengine', ENGINE_CUDA);
      await page.click('#rbbtn');
      await page.waitForFunction(() => /новый bundle|ERR/.test((document.getElementById('rbstatus') || {}).textContent || ''));
      const rstat = await page.$eval('#rbstatus', (e) => e.textContent);
      if (/ERR/.test(rstat)) fails.push('перепривязка: ' + rstat);
      else {
        const after = await tapi('/bundles?model=' + ggufSha);
        const afterB = (after.json && after.json.bundles || []);
        const fresh = afterB.filter((x) => !beforeIds.includes(x.bundle_id));
        const hasCuda = afterB.some((x) => String(x.engine_image || '').includes(ENGINE_CUDA));
        if (!fresh.length && !hasCuda) fails.push('после перепривязки нет bundle с движком ' + ENGINE_CUDA.slice(0, 20));
        else step('S4 перепривязка (другой реальный движок): всего bundle=' + afterB.length
                  + (fresh.length ? ', новый ' + fresh[0].bundle_id : ', движок уже был привязан (идемпотентно)'));
      }
    }

    // ---------- S1: реальная не-LLM модель (safetensors) ----------
    let stSha = null, stScan = null;
    if (fs.existsSync(SAFETENSORS)) {
      const crypto = require('crypto');
      stSha = crypto.createHash('sha256').update(fs.readFileSync(SAFETENSORS)).digest('hex');
      await page.click('#downloads .tab[data-tab="tab-models"]');
      await page.waitForSelector('#f input[type=file]');
      const nm = 'real-model-' + Date.now() + '.safetensors';
      const tmp = path.join('/tmp', nm); fs.copyFileSync(SAFETENSORS, tmp);
      const inp = await page.$('#f input[type=file]'); await inp.uploadFile(tmp);
      await page.click('#f button[type=submit]');
      await page.waitForFunction((n) => document.body.innerText.includes(n), { timeout: 180000 }, nm);
      step('S1: реальная safetensors-модель загружена: ' + nm);
      // ждём завершения скана и открываем карточку
      const sc = await tapi('/scans');
      const rec = (sc.json && sc.json.scans || []).find((s) => s.name === nm);
      if (!rec) fails.push('нет записи скана для ' + nm);
      else {
        stScan = rec.scan_id;
        for (let i = 0; i < 60; i++) {
          const r = await tapi('/scans/' + rec.scan_id);
          if (r.json && r.json.state === 'done') { step('S1: скан завершён, вердикт=' + (r.json.verdict || '—') + ', покрытие=' + JSON.stringify((r.json.coverage || {}).complete)); break; }
          if (r.json && r.json.state === 'error') { fails.push('S1: скан error: ' + (r.json.reason || '')); break; }
          await sleep(3000);
        }
        await page.goto(BASE + '/artifact/' + rec.scan_id, { waitUntil: 'domcontentloaded' });
        const card = await page.evaluate(() => document.body.innerText);
        if (!/Malicious|Safe|Inconclusive|Dangerous|Needs review/i.test(card)) fails.push('в карточке S1 нет вердикта');
        step('S1: карточка артефакта отрисована (вердикт на странице)');
      }
      fs.unlinkSync(tmp);
    } else fails.push('нет файла safetensors: ' + SAFETENSORS);

    // ---------- S3: реальный архив ----------
    if (fs.existsSync(ARCHIVE)) {
      await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
      await page.waitForSelector('#f input[type=file]');
      const nm = 'real-pack-' + Date.now() + '.zip';
      const tmp = path.join('/tmp', nm); fs.copyFileSync(ARCHIVE, tmp);
      const inp = await page.$('#f input[type=file]'); await inp.uploadFile(tmp);
      await page.click('#f button[type=submit]');
      await page.waitForFunction((n) => document.body.innerText.includes(n), { timeout: 300000 }, nm);
      step('S3: реальный архив загружен: ' + nm);
      const sc = await tapi('/scans');
      const rec = (sc.json && sc.json.scans || []).find((s) => s.name === nm);
      if (!rec) fails.push('нет записи скана для архива');
      else {
        for (let i = 0; i < 80; i++) {
          const r = await tapi('/scans/' + rec.scan_id);
          if (r.json && ['done', 'error'].includes(r.json.state)) {
            const j = r.json;
            const members = (j.findings || []).filter((f) => /zip|archive|member|entry/i.test(String(f.rule_id || f.id || ''))).length;
            step('S3: архив обработан, state=' + j.state + ', вердикт=' + (j.verdict || '—') + ', находок=' + (j.findings || []).length);
            if (j.state !== 'done') fails.push('S3: скан архива не завершился: ' + (j.reason || ''));
            break;
          }
          await sleep(3000);
        }
      }
      fs.unlinkSync(tmp);
    } else fails.push('нет файла архива: ' + ARCHIVE);

    // ---------- S5: CI-gate (реальный образ + модель) ----------
    const modelForGate = ggufSha || stSha;
    if (modelForGate) {
      const g = await tapi('/gate?image=' + encodeURIComponent('ghcr.io/ggml-org/llama.cpp@' + ENGINE_CUDA) + '&model=' + modelForGate);
      const dec = g.json && g.json.decision;
      if (!dec) fails.push('S5: /gate не вернул decision (' + JSON.stringify(g.json).slice(0, 120) + ')');
      else step('S5: CI-gate decision=' + dec + ' bundle=' + (g.json.bundle_id || '—'));
    }

    // ---------- наблюдаемость ----------
    const slo = await tapi('/v3/slo');
    step('v3/slo доступен: ' + JSON.stringify(slo.json).slice(0, 80));
  } catch (e) {
    fails.push(String(e && e.message ? e.message : e));
  } finally {
    await browser.close();
  }

  if (bad.length) { console.log('[e2e] HTTP>=400 после входа:'); bad.slice(0, 10).forEach((b) => console.log('   -', b)); }
  if (fails.length) { console.log('[e2e] FAIL:'); fails.forEach((f) => console.log('   -', f)); process.exit(1); }
  console.log('[e2e] OK: полный операторский сценарий с реальными моделями пройден (' + steps.length + ' шагов)');
})();
