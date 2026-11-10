import asyncio
from playwright.async_api import async_playwright
async def main():
    async with async_playwright() as p:
        b=await p.chromium.launch(); pg=await b.new_page(viewport={"width":1600,"height":1000}); errs=[]
        pg.on("pageerror",lambda e:errs.append(str(e)))
        await pg.goto("file:///mnt/session/outputs/APT_Threat_Map.html"); await pg.wait_for_selector("#loading",state="detached",timeout=60000)
        await pg.click("#nav button[data-t=trace]"); await pg.wait_for_timeout(800)
        print(await pg.evaluate("$('#trG').options.length"), await pg.evaluate("$('#trGn').textContent"))
        await pg.fill("#trQ2","lazarus"); await pg.wait_for_timeout(500)
        print("após filtro:", await pg.evaluate("TR.e.n"))
        await pg.fill("#trQ2",""); await pg.dispatch_event("#trQ2","input")
        await pg.select_option("#trG", str(await pg.evaluate("E.find(e=>e.m==='G0016').i"))); await pg.wait_for_timeout(800)
        print("selecionado:", await pg.evaluate("TR.e.n"), await pg.evaluate("document.querySelectorAll('#trcols .ti').length"))
        await pg.click("#trNext"); await pg.wait_for_timeout(500); print("next:", await pg.evaluate("TR.e.n"))
        await pg.evaluate("goTrace(E.find(e=>e.m==='G0032').i)"); await pg.wait_for_timeout(500); print("goTrace:", await pg.evaluate("TR.e.n"), await pg.evaluate("$('#trG').value==TR.e.i"))
        await pg.screenshot(path="/tmp/shots/tr_fix.png"); print("ERR",errs); await b.close()
asyncio.run(main())
