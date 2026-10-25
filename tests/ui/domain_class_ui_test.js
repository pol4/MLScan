#!/usr/bin/env node
/* U9 UI-тест: редактор «домен → класс policy» (админ) — сохранение переопределения. */
'use strict';
const fs=require('fs'),os=require('os'),path=require('path');
const puppeteer=require('puppeteer-core');
const BASE=process.env.MLSCAN_UI_URL||'http://analytics.mlscan.local:30217';
const USER=process.env.MLSCAN_UI_USER||'admin', PASS=process.env.MLSCAN_UI_PASS||'Admin-MLScan-1';
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
    await page.waitForSelector('#dcdomain',{timeout:15000});
    await page.type('#dcdomain','Правонарушение');
    await page.type('#dcclass','illegal_activity_manual');
    await page.click('#dcsave');
    await page.waitForFunction(()=>{const e=document.getElementById('dcstatus');return e&&/saved/.test(e.textContent);},{timeout:30000});
    const st=await page.$eval('#dcstatus',e=>e.textContent);
    if(!/saved/.test(st)) fails.push('нет подтверждения сохранения: '+st);
    console.log('[ui-domain] сохранение переопределения:', st);
  }catch(e){ fails.push(String(e&&e.message?e.message:e)); }
  finally{ await browser.close(); }
  if(fails.length){ console.log('[ui-domain] FAIL:'); fails.forEach(f=>console.log('   -',f)); process.exit(1); }
  console.log('[ui-domain] OK');
})();
