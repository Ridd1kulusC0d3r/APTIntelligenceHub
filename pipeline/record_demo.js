// Grava os clipes de demonstração (Playwright). Uso: node pipeline/record_demo.js [map|graph|trace|detect|theme]
// Depois: bash pipeline/make_media.sh  (converte para MP4/GIF em assets/media)
const { chromium } = require('playwright');
const fs=require('fs');
const path=require('path'),os=require('os');
const URL=process.env.APT_URL||('file://'+path.resolve(__dirname,'..','index.html'));
const RAW=process.env.APT_RAW||path.join(os.tmpdir(),'apt-rec');fs.mkdirSync(RAW,{recursive:true});
const CURSOR=`(()=>{const d=document.createElement('div');d.id='__cur';d.style.cssText='position:fixed;left:0;top:0;width:18px;height:18px;margin:-9px 0 0 -9px;border-radius:50%;background:rgba(240,136,90,.35);border:2px solid #f0885a;z-index:2147483647;pointer-events:none;transition:transform .05s linear';document.documentElement.appendChild(d);addEventListener('mousemove',e=>{d.style.transform='translate('+e.clientX+'px,'+e.clientY+'px)'},true)})()`;
async function go(p,x,y,steps=25){await p.mouse.move(x,y,{steps});}
async function focusTo(p,sel){await p.evaluate((sel)=>{const e=document.querySelector(sel),f=document.getElementById('fbar');const y=e.getBoundingClientRect().top+scrollY-(f?f.offsetHeight:0)-10;window.scrollTo({top:y,behavior:'instant'})},sel);await p.waitForTimeout(500);}
async function clickEl(p,sel,opts={}){const e=p.locator(sel).first();await e.scrollIntoViewIfNeeded();const b=await e.boundingBox();if(!b)return false;await go(p,b.x+b.width/2,b.y+b.height/2);await p.waitForTimeout(250);await p.mouse.down();await p.mouse.up();return true;}
const SEG={
 async map(p){
  await p.waitForTimeout(1500);
  await clickEl(p,'[data-preset="br"]');await p.waitForTimeout(1800);
  await focusTo(p,'nav');
  const c=p.locator('.mks circle').first();
  if(await c.count()){const bb=await c.boundingBox();if(bb){await go(p,bb.x+bb.width/2,bb.y+bb.height/2);await p.waitForTimeout(900);await p.mouse.down();await p.mouse.up();await p.waitForTimeout(2200);}}
  await clickEl(p,'#fClr');await p.waitForTimeout(1500);
 },
 async graph(p){
  await clickEl(p,'nav button[data-t="graph"]');await focusTo(p,'nav');await p.waitForTimeout(3500);
  const g=await p.locator('#gcv').boundingBox();
  await p.mouse.move(g.x+g.width*.3,g.y+g.height*.4,{steps:20});
  for(let i=0;i<4;i++){await p.mouse.move(g.x+g.width*(.3+.12*i),g.y+g.height*(.4+.05*i),{steps:18});await p.waitForTimeout(500);}
  await p.mouse.wheel(0,-300);await p.waitForTimeout(1200);await p.mouse.wheel(0,300);await p.waitForTimeout(1500);
 },
 async trace(p){
  await clickEl(p,'nav button[data-t="trace"]');await p.waitForTimeout(2500);
  await focusTo(p,'#trwrap');
  const items=p.locator('#trcols .tcol:nth-child(2) .ti');const n=Math.min(await items.count(),3);
  for(let i=0;i<n;i++){const b=await items.nth(i).boundingBox();if(!b)continue;await go(p,b.x+b.width/2,b.y+b.height/2);await p.waitForTimeout(300);await p.mouse.down();await p.mouse.up();await p.waitForTimeout(1700);}
 },
 async detect(p){
  await clickEl(p,'nav button[data-t="det"]');await focusTo(p,'nav');await p.waitForTimeout(2800);
  await p.mouse.wheel(0,350);await p.waitForTimeout(1500);
  await clickEl(p,'nav button[data-t="mx"]');await focusTo(p,'nav');await p.waitForTimeout(3000);
  await p.mouse.wheel(0,300);await p.waitForTimeout(1800);
 },
 async theme(p){
  await p.waitForTimeout(1200);
  await clickEl(p,'#theme');await p.waitForTimeout(1500);await focusTo(p,'nav');await p.waitForTimeout(1800);await p.evaluate(()=>scrollTo({top:0,behavior:'instant'}));await p.waitForTimeout(800);await clickEl(p,'#theme');await p.waitForTimeout(2000);
 }
};
(async()=>{
 const b=await chromium.launch();
 const only=process.argv[2];
 const times={};
 for(const [name,fn] of Object.entries(SEG)){
  if(only&&only!==name)continue;
  const ctx=await b.newContext({viewport:{width:1600,height:900},colorScheme:'dark',recordVideo:{dir:RAW,size:{width:1280,height:720}}});
  const p=await ctx.newPage();await p.addInitScript(CURSOR);
  const t0=Date.now();
  await p.goto(URL);await p.waitForSelector('#loading',{state:'detached',timeout:90000});await p.waitForTimeout(800);
  const ready=(Date.now()-t0)/1000;
  await fn(p);
  const v=p.video();await ctx.close();const vp=await v.path();
  fs.renameSync(vp,path.join(RAW,name+'.webm'));times[name]=ready;console.log(name,'ready at',ready.toFixed(1));
 }
 fs.writeFileSync(path.join(RAW,'times.json'),JSON.stringify(times));
 await b.close();
})();
