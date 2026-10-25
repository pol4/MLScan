#!/usr/bin/env node
/* L0 UI-тест: явное указание типа артефакта — при выборе «Образ инференс-движка» показывается
 * уведомление, что грузится контейнерный образ (engine image). См. Arch_v3/18. */
'use strict';
const fs = require('fs'); const os = require('os'); const path = require('path');
const puppeteer = require('puppeteer-core');
const BASE = process.env.MLSCAN_UI_URL || 'http://analytics.mlscan.local:30217';
const USER = process.env.MLSCAN_UI_USER || 'admin';
const PASS = process.env.MLSCAN_UI_PASS || 'Admin-MLScan-1';
function findChrome(){ if(process.env.CHROME_PATH&&fs.existsSync(process.env.CHROME_PATH))return process.env.CHROME_PATH;
  const c=path.join(os.homedir(),'.cache','puppeteer','chrome');
  if(fs.existsSync(c))for(const d of fs.readdirSync(c)){const p=path.join(c,d,'chrome-linux64','chrome');if(fs.existsSync(p))return p;}
  for(const p of ['/usr/bin/google-chrome-stable','/usr/bin/google-chrome','/snap/bin/chromium'])if(fs.existsSync(p))return p;
  throw new Error('Chrome не найден'); }
(async()=>{
  const fails=[];
  const browser=await puppeteer.launch({executablePath:findChrome(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage','--ignore-certificate-errors']});
  const page=await browser.newPage();
  try{
    await page.goto(`${BASE}/login`,{waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForSelector('input[name=username]',{timeout:15000});
    await page.type('input[name=username]',USER); await page.type('input[name=password]',PASS);
    await Promise.all([page.waitForNavigation({waitUntil:'domcontentloaded',timeout:30000}),page.click('button[type=submit]')]);
    await page.waitForSelector('#kind',{timeout:15000});
    // по умолчанию — модель, уведомление скрыто
    let vis = await page.$eval('#kindnotice', el=>getComputedStyle(el).display !== 'none');
    if (vis) fails.push('уведомление видно по умолчанию (ожидалось скрыто)');
    await page.select('#kind','engine_image');
    vis = await page.$eval('#kindnotice', el=>getComputedStyle(el).display !== 'none');
    const txt = await page.$eval('#kindnotice', el=>el.textContent||'');
    if(!vis) fails.push('уведомление не показано при engine_image');
    if(!/container image|контейнерн/i.test(txt)) fails.push('нет явного текста про образ ('+txt.slice(0,60)+')');
    await page.select('#kind','model');
    vis = await page.$eval('#kindnotice', el=>getComputedStyle(el).display !== 'none');
    if(vis) fails.push('уведомление не скрылось при возврате к модели');
    console.log('[ui-kind] тип артефакта и уведомление об образе работают');
  }catch(e){ fails.push(String(e&&e.message?e.message:e)); }
  finally{ await browser.close(); }
  if(fails.length){ console.log('[ui-kind] FAIL:'); fails.forEach(f=>console.log('   -',f)); process.exit(1); }
  console.log('[ui-kind] OK');
})();
