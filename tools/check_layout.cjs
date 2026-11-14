// Start tools/preview.py first. Requires optional Playwright with Chromium and WebKit.
const {chromium,webkit}=require('playwright');
const assert=require('node:assert/strict');
const path=require('node:path');
const output=process.env.GUARDTOWARR_SCREENSHOTS||require('node:os').tmpdir();
(async()=>{for(const [name,engine] of Object.entries({chromium,webkit})){
 const browser=await engine.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}});let errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:19595');await page.waitForFunction(()=>document.querySelector('#shortcutPanel a'));
 await page.click('#searchToggle');await page.fill('#searchInput','example');await page.evaluate(()=>runSearch());await page.waitForSelector('.poster-art img');await page.waitForFunction(()=>[...document.querySelectorAll('.poster-art img')].every(i=>i.naturalWidth===1200));
 for(const width of [1440,768,390]){await page.setViewportSize({width,height:1000});await page.waitForTimeout(200);
 const sizes=await page.locator('.poster-art').evaluateAll(nodes=>nodes.map(n=>{const r=n.getBoundingClientRect(),i=n.querySelector('img').getBoundingClientRect();return {w:r.width,h:r.height,iw:i.width,ih:i.height}}));
 assert(sizes.length>=6);for(const r of sizes){assert(Math.abs(r.h/r.w-1.5)<0.03,JSON.stringify(r));assert(Math.abs(r.iw-r.w)<2);assert(Math.abs(r.ih-r.h)<2);}
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'horizontal overflow '+width);
 await page.screenshot({path:path.join(output,`${name}-${width}.png`),fullPage:true});}
 await page.setViewportSize({width:1440,height:1000});await page.evaluate(()=>openSettings());await page.waitForSelector('#storageMode',{state:'attached'});
 assert(await page.locator('[data-svc="qbittorrent"][data-field="username"]').count()||await page.locator('input[value="demo-user"]').count());
 await page.waitForTimeout(500);
 assert(await page.locator('#settingsOverlay').evaluate(n=>n.scrollTop===0),'settings must open at top');
 await page.screenshot({path:path.join(output,`${name}-settings.png`),fullPage:true});
 await page.evaluate(()=>{document.getElementById('storageMode').value='off';document.getElementById('allowedHosts').value='https://dashboard.example.com/settings';});
 const cfg=await page.evaluate(()=>{collectSettings();return fullConfig;});assert.equal(cfg.ui.show_storage,false);assert.deepEqual(cfg.allowed_hosts,['dashboard.example.com']);assert.equal(cfg.services.qbittorrent.username,'demo-user');assert.equal(cfg.services.qbittorrent.password,'demo-password');assert.equal(cfg.services.qbittorrent.api_key,'');
 const override=page.locator('[data-link-field="remote_override"]').first();
 page.once('dialog',d=>d.dismiss());await override.click();assert.equal(await override.isChecked(),false);
 page.once('dialog',d=>d.accept());await override.click();assert.equal(await override.isChecked(),true);
 assert.equal(await page.evaluate(()=>collectShortcuts()[0].remote_override),true);
 await override.uncheck();
 await page.evaluate(()=>setSettingsTab('services'));await page.waitForTimeout(500);
 await page.screenshot({path:path.join(output,`${name}-services.png`),fullPage:true});
 await page.evaluate(()=>closeSettings());
 const labels=(await page.locator('#shortcutPanel a').allTextContents()).map(s=>s.slice(0,-2).trim());
 for(const label of ['Sonarr','Movies','Movies 4K','qBittorrent'])assert(labels.includes(label),label);
 let submitted;
 await page.route('**/api/config',async route=>{
   if(route.request().method()!=='POST')return route.continue();
   submitted=route.request().postDataJSON();
   await route.fulfill({status:500,contentType:'application/json',body:JSON.stringify({ok:false,error:'Fixture save failure'})});
 });
 await page.evaluate(()=>{pickedServices=new Set(['qbittorrent']);document.getElementById('onboardOverlay').classList.add('show');onboardToStep2();});
 await page.locator('#onboard-qbittorrent-password').fill(' password with spaces ');
 await page.evaluate(()=>saveOnboard());
 assert.equal(submitted.config.services.qbittorrent.password,' password with spaces ');
 assert(await page.locator('#onboardOverlay').evaluate(n=>n.classList.contains('show')),'failed setup must stay open');
 await page.evaluate(()=>skipOnboard());
 assert(await page.locator('#onboardOverlay').evaluate(n=>n.classList.contains('show')),'failed skip must stay open');
 await page.unroute('**/api/config');
 await page.evaluate(()=>{closeOnboard();});await page.evaluate(()=>openSettings());
 await page.evaluate(()=>{document.getElementById('storageMode').value='selected';document.getElementById('storageInstances').value='radarr_4k';document.getElementById('instanceApp').value='radarr';document.getElementById('portInput').value='19600';addInstance();});
 assert(await page.locator('#storageInstances option[value="radarr_2"]').count());
 assert.equal(await page.locator('#storageInstances').inputValue(),'radarr_4k');
 page.once('dialog',d=>d.accept());await page.evaluate(()=>removeInstance('radarr_4k'));
 assert.equal(await page.locator('#storageInstances option[value="radarr_4k"]').count(),0);
 assert.deepEqual(await page.evaluate(()=>fullConfig.ui.storage_instances),[]);
 assert.equal(await page.locator('#storageMode').inputValue(),'selected');await page.evaluate(()=>setSettingsTab('general'));await page.locator('#storageEmpty').waitFor({state:'visible'});assert(await page.locator('#storageEmpty').isVisible());
 assert.equal(await page.evaluate(()=>{collectSettings();return fullConfig.ui.storage_mode;}),'selected');
 await page.route('**/api/config',r=>r.request().method()==='POST'?r.fulfill({contentType:'application/json',body:'{"ok":true}'}):r.continue());
 await page.evaluate(()=>saveSettings());assert((await page.locator('#toast').textContent()).includes('Restart'));
 let releaseFirst,releaseSecond;const first=new Promise(r=>releaseFirst=r),second=new Promise(r=>releaseSecond=r);let requests=0;
 await page.route('**/api/profiles',async route=>{const id=++requests;await(id===1?first:second);await route.fulfill({contentType:'application/json',body:JSON.stringify({ok:true,profiles:[{id,name:'Profile '+id}],roots:[{id,path:'/library'+id}]})});});
 await page.evaluate(()=>{window._results=[{title:'First',tmdbId:1},{title:'Second',tmdbId:2}];void addMedia(0);});
 await page.waitForTimeout(100);await page.evaluate(()=>{closeConfirm();void addMedia(1);});await page.waitForTimeout(100);
 releaseSecond();await page.waitForTimeout(150);releaseFirst();await page.waitForTimeout(150);
 assert.equal(await page.locator('#profileSelect').inputValue(),'2');assert.equal(await page.locator('#rootSelect').inputValue(),'2');
 assert.deepEqual(errors,[]);console.log(name+': desktop/tablet/mobile posters and overflow checks passed');await browser.close();
}})().catch(e=>{console.error(e);process.exit(1)});


