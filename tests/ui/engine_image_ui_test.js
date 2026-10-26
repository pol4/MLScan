#!/usr/bin/env node
/* U1 UI-тест: панель импорта образа движка (по digest) + бейдж «Engine image» в карточке артефакта. */
'use strict';
const fs=require('fs'),os=require('os'),path=require('path');
const puppeteer=require('puppeteer-core');
const BASE=process.env.MLSCAN_UI_URL||'http://analytics.mlscan.local:30217';
const USER=process.env.MLSCAN_UI_USER||'admin', PASS=process.env.MLSCAN_UI_PASS||'Admin-MLScan-1';
const DIG='sha256:'+'a'.repeat(64);
function chrome(){ if(process.env.CHROME_PATH&&fs.existsSync(process.env.CHROME_PATH))return process.env.CHROME_PATH;
  const c=path.join(os.homedir(),'.cache','puppeteer','chrome');
  if(fs.existsSync(c))for(const d of fs.readdirSync(c)){const p=path.join(c,d,'chrome-linux64','chrome');if(fs.existsSync(p))return p;}
  for(const p of ['/usr/bin/google-chrome-stable','/usr/bin/google-chrome','/snap/bin/chromium'])if(fs.existsSync(p))return p;
  throw new Error('Chrome не найден'); }
(async()=>{
  const fails=[]; const bad=[];
  const browser=await puppeteer.launch({executablePath:chrome(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage','--ignore-certificate-errors']});
  const page=await browser.newPage();
  page.on('response',r=>{const u=r.url();if(r.status()>=400&&!/favicon\.ico$/.test(u))bad.push(`${r.status()} ${u}`);});
  try{
    await page.goto(BASE+'/login',{waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForSelector('input[name=username]',{timeout:15000});
    await page.type('input[name=username]',USER); await page.type('input[name=password]',PASS);
    await Promise.all([page.waitForNavigation({waitUntil:'domcontentloaded',timeout:30000}),page.click('button[type=submit]')]);
    bad.length=0;
    // 1) панель импорта образа движка
    await page.click('#downloads .tab[data-tab="tab-engines"]');
    await page.waitForFunction(()=>getComputedStyle(document.getElementById('tab-engines')).display!=='none',{timeout:10000});
    await page.waitForSelector('#imgref',{timeout:15000});
    await page.type('#imgref', `mlscan-registry/team/vllm@${DIG}`);
    await page.click('#imgimport-btn');
    await page.waitForFunction(()=>{const e=document.getElementById('imgstatus');return e&&e.textContent.length>0;},{timeout:30000});
    const st=await page.$eval('#imgstatus',e=>e.textContent);
    console.log('[ui-engine] импорт образа:', st);
    // 2) бейдж «Engine image» в карточке после загрузки с kind=engine_image
    await page.click('#downloads .tab[data-tab="tab-models"]');
    const name=`uitest-engine-${Date.now()}.bin`;
    const tmp=path.join(os.tmpdir(),name); fs.writeFileSync(tmp,Buffer.alloc(64*1024,5));
    await page.select('#kind','engine_image');
    const input=await page.$('#f input[type=file]'); await input.uploadFile(tmp);
    await page.click('#f button[type=submit]');
    await page.waitForFunction(n=>document.body&&document.body.innerText.includes(n),{timeout:60000},name);
    const hasBadge=await page.evaluate(()=>/Engine image/.test(document.body.innerText));
    if(!hasBadge) fails.push('нет бейджа «Engine image» в карточке');
    fs.unlinkSync(tmp);
  }catch(e){ fails.push(String(e&&e.message?e.message:e)); }
  finally{ await browser.close(); }
  if(bad.length){ console.log('[ui-engine] HTTP>=400:',bad.slice(0,5)); fails.push(...bad.slice(0,5).map(x=>'HTTP '+x)); }
  if(fails.length){ console.log('[ui-engine] FAIL:'); fails.forEach(f=>console.log('   -',f)); process.exit(1); }
  console.log('[ui-engine] OK');
})();
