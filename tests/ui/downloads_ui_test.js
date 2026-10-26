#!/usr/bin/env node
/* §10 UI-тест: раздел «Загрузки» (4 подзакладки), гейтинг движка, токен, перепривязка-панель. */
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
  const bad=[]; page.on('response',r=>{const u=r.url();if(r.status()>=400 && !/favicon\.ico$/.test(u)) bad.push(r.status()+' '+u);});
  page.on('pageerror',e=>fails.push('JS: '+String(e)));
  page.on('console',m=>{if(m.type()==='error' && !/Failed to load resource/.test(m.text()))fails.push('console: '+m.text());});
  try{
    await page.goto(BASE+'/login',{waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForSelector('input[name=username]',{timeout:15000});
    await page.type('input[name=username]',USER); await page.type('input[name=password]',PASS);
    await Promise.all([page.waitForNavigation({waitUntil:'domcontentloaded',timeout:30000}),page.click('button[type=submit]')]);
    await page.waitForSelector('#downloads',{timeout:15000});
    // подзакладки
    const tabs=await page.$$eval('#downloads .tab', els=>els.map(e=>e.dataset.tab));
    for(const t of ['tab-models','tab-local','tab-engines','tab-hf'])
      if(!tabs.includes(t)) fails.push('нет подзакладки '+t);
    await page.click('#downloads .tab[data-tab="tab-engines"]');
    await page.waitForFunction(()=>getComputedStyle(document.getElementById('tab-engines')).display!=='none',{timeout:10000})
      .catch(()=>fails.push('подзакладка «Движки» не показалась'));
    // список скачанных движков
    await page.waitForFunction(()=>{const s=document.getElementById('englist');return s&&s.options.length>1;},{timeout:20000})
      .catch(()=>fails.push('список движков пуст (нет registry_images?)'));
    // HF-таб: гейтинг
    await page.click('#downloads .tab[data-tab="tab-hf"]');
    await page.waitForFunction(()=>getComputedStyle(document.getElementById('tab-hf')).display!=='none',{timeout:10000})
      .catch(()=>fails.push('подзакладка HF не показалась'));
    await page.type('#hfquery','tinyllama'); await page.type('#hftype','text-generation');
    await page.click('#hfsearch-btn');
    await page.waitForFunction(()=>/TinyLlama/.test(document.getElementById('hfresults').textContent),{timeout:30000});
    // без движка — отказ
    await page.$eval('#hfengine',e=>e.value='');
    const btn=await page.$('#hfresults button[data-repo]'); await btn.click();
    await page.waitForFunction(()=>/ERR/.test((document.getElementById('hfstatus')||{}).textContent||''),{timeout:15000})
      .catch(()=>fails.push('нет отказа при загрузке без движка'));
    // с движком — старт загрузки
    const val=await page.$eval('#englist',e=>e.options[1]&&e.options[1].value);
    await page.select('#hfengine', val);
    await page.$eval('#hfengine',e=>e.dispatchEvent(new Event('change',{bubbles:true})));
    const btn2=await page.$('#hfresults button[data-repo]'); await btn2.click();
    await page.waitForFunction(()=>/queued|download/.test((document.getElementById('hfstatus')||{}).textContent||''),{timeout:20000})
      .catch(()=>fails.push('загрузка с движком не стартовала'));
    // токен
    await page.type('#hftoken','hf_test_token_1234');
    await page.click('#hftokensave');
    await page.waitForFunction(()=>/saved hf_\*\*\*/.test((document.getElementById('hftokenstatus')||{}).textContent||''),{timeout:15000})
      .catch(()=>fails.push('токен не сохранён/не замаскирован'));
    console.log('[ui-downloads] подзакладки/гейтинг/токен отработали');
  }catch(e){ fails.push(String(e&&e.message?e.message:e)); }
  finally{ await browser.close(); }
  if(bad.length){ console.log('[ui-downloads] bad responses:'); bad.slice(0,8).forEach(b=>console.log('   -',b)); }
  if(fails.length){ console.log('[ui-downloads] FAIL:'); fails.forEach(f=>console.log('   -',f)); process.exit(1); }
  console.log('[ui-downloads] OK');
})();
