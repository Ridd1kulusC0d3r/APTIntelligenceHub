import asyncio, sys
from playwright.async_api import async_playwright
URL = "file:///mnt/session/outputs/APT_Threat_Map.html"
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1600, "height": 1000})
        errs = []
        pg.on("console", lambda m: errs.append(("console." + m.type, m.text)) if m.type in ("error", "warning") else None)
        pg.on("pageerror", lambda e: errs.append(("pageerror", str(e))))
        await pg.goto(URL)
        await pg.wait_for_selector("#loading", state="detached", timeout=60000)
        await pg.wait_for_timeout(1500)
        await pg.screenshot(path="/tmp/shots/01_map.png")
        # clique no Brasil preset
        await pg.click("[data-preset=br]"); await pg.wait_for_timeout(1200)
        await pg.screenshot(path="/tmp/shots/02_map_br.png")
        await pg.click("#fClr"); await pg.wait_for_timeout(500)
        for t in ["graph", "trace", "prio", "det", "mx", "grp", "src"]:
            await pg.click(f"#nav button[data-t={t}]"); await pg.wait_for_timeout(2500 if t == "graph" else 1200)
            await pg.screenshot(path=f"/tmp/shots/tab_{t}.png")
        print("ERRORS:", len(errs))
        for e in errs[:30]: print(e)
        await b.close()
asyncio.run(main())
