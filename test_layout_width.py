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
        
        # Bounding boxes of layouts
        boxes = await page.evaluate("""() => {
            const getBox = id => {
                const el = document.getElementById(id) || document.querySelector('.' + id);
                if (!el) return 'Not found';
                const rect = el.getBoundingClientRect();
                return {
                    id: el.id,
                    class: el.className,
                    width: rect.width,
                    height: rect.height,
                    display: window.getComputedStyle(el).display,
                    boxSizing: window.getComputedStyle(el).boxSizing
                };
            };
            return {
                page: getBox('page-ai-analyst'),
                layout: getBox('ai-layout'),
                chatPanel: getBox('ai-chat-panel'),
                inputWrap: getBox('chat-input-wrap'),
                chatInput: getBox('chat-input'),
                chatSend: getBox('chat-send')
            };
        }""")
        
        print("Bounding Boxes:")
        for name, box in boxes.items():
            print(f"  {name}: {box}")
            
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
