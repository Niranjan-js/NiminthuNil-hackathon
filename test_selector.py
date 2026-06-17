import asyncio
import sys
from playwright.async_api import async_playwright

sys.stdout.reconfigure(encoding='utf-8')

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        await page.goto("http://127.0.0.1:3000", wait_until="networkidle")
        await page.locator("text=admin@niravan.ai").click()
        await asyncio.sleep(4)
        
        await page.click("#nav-ai-analyst", force=True)
        await asyncio.sleep(2)
        
        # Get details of #chat-send
        details = await page.evaluate("""() => {
            const el = document.getElementById('chat-send');
            if (!el) return 'Not found';
            const rect = el.getBoundingClientRect();
            const style = window.getComputedStyle(el);
            return {
                html: el.outerHTML,
                width: rect.width,
                height: rect.height,
                display: style.display,
                visibility: style.visibility,
                opacity: style.opacity,
                pointerEvents: style.pointerEvents,
                position: style.position,
                zIndex: style.zIndex,
                parentDisplay: window.getComputedStyle(el.parentElement).display,
                parentWidth: el.parentElement.getBoundingClientRect().width
            };
        }""")
        print("chat-send details:", details)
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
