#!/usr/bin/env node
/* L3 UI-тест: администратор загружает XLSX-набор тестов через UI; показывается активная версия. */
'use strict';
const fs=require('fs'),os=require('os'),path=require('path');
const puppeteer=require('puppeteer-core');
const BASE=process.env.MLSCAN_UI_URL||'http://analytics.mlscan.local:30217';
const USER=process.env.MLSCAN_UI_USER||'admin', PASS=process.env.MLSCAN_UI_PASS||'Admin-MLScan-1';
const XLSX_B64='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';
function chrome(){ if(process.env.CHROME_PATH&&fs.existsSync(process.env.CHROME_PATH))return process.env.CHROME_PATH;
  const c=path.join(os.homedir(),'.cache','puppeteer','chrome');
  if(fs.existsSync(c))for(const d of fs.readdirSync(c)){const p=path.join(c,d,'chrome-linux64','chrome');if(fs.existsSync(p))return p;}
  for(const p of ['/usr/bin/google-chrome-stable','/usr/bin/google-chrome','/snap/bin/chromium'])if(fs.existsSync(p))return p;
  throw new Error('Chrome не найден'); }
(async()=>{
  const fails=[];
  const browser=await puppeteer.launch({executablePath:chrome(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage','--ignore-certificate-errors']});
  const page=await browser.newPage();
  try{
    await page.goto(BASE+'/login',{waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForSelector('input[name=username]',{timeout:15000});
    await page.type('input[name=username]',USER); await page.type('input[name=password]',PASS);
    await Promise.all([page.waitForNavigation({waitUntil:'domcontentloaded',timeout:30000}),page.click('button[type=submit]')]);
    await page.waitForSelector('#psfile',{timeout:15000});
    const f=path.join(os.tmpdir(),'ui_ps_test.xlsx');
    fs.writeFileSync(f,Buffer.from(XLSX_B64,'base64'));
    const input=await page.$('#psfile'); await input.uploadFile(f);
    await page.waitForFunction(()=>{const e=document.getElementById('psstatus');return e&&/OK ps-/.test(e.textContent);},{timeout:30000});
    const txt=await page.$eval('#psstatus',e=>e.textContent);
    if(!/cases=/.test(txt)) fails.push('нет counts в статусе: '+txt);
    console.log('[ui-promptset] загрузка XLSX через UI: '+txt);
    fs.unlinkSync(f);
  }catch(e){ fails.push(String(e&&e.message?e.message:e)); }
  finally{ await browser.close(); }
  if(fails.length){ console.log('[ui-promptset] FAIL:'); fails.forEach(x=>console.log('   -',x)); process.exit(1); }
  console.log('[ui-promptset] OK');
})();
