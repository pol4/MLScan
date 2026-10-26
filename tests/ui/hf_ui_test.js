#!/usr/bin/env node
/* U11 UI-тест: панель Hugging Face (поиск с фильтрами + фоновая загрузка, статус в UI). */
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
    await page.click('#downloads .tab[data-tab="tab-hf"]');
    await page.waitForFunction(()=>getComputedStyle(document.getElementById('tab-hf')).display!=='none',{timeout:10000});
    await page.waitForSelector('#hfquery',{timeout:15000});
    await page.type('#hfquery','tinyllama');
    await page.type('#hftype','text-generation');
    await page.select('#hfquant','Q5_K_M');
    await page.waitForFunction(()=>{const s=document.getElementById('hfengine');return s&&s.options.length>1;},{timeout:20000});
    const engval=await page.$eval('#hfengine', e=>e.options[1].value);
    await page.select('#hfengine', engval);
    await page.click('#hfsearch-btn');
    await page.waitForFunction(()=>{const e=document.getElementById('hfresults');return e&&/TinyLlama/.test(e.textContent);},{timeout:30000});
    console.log('[ui-hf] результаты поиска получены');
    const btn=await page.$('#hfresults button[data-repo]');
    if(!btn) fails.push('нет кнопки download в результатах');
    else{
      await btn.click();
      await page.waitForFunction(()=>{const e=document.getElementById('hfstatus');return e&&/done/.test(e.textContent);},{timeout:60000});
      console.log('[ui-hf] загрузка завершена:', await page.$eval('#hfstatus',e=>e.textContent));
    }
  }catch(e){ fails.push(String(e&&e.message?e.message:e)); }
  finally{ await browser.close(); }
  if(fails.length){ console.log('[ui-hf] FAIL:'); fails.forEach(f=>console.log('   -',f)); process.exit(1); }
  console.log('[ui-hf] OK');
})();
