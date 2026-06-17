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
        
        async def check_input_rects(label):
            details = await page.evaluate("""() => {
                const getInfo = (idOrSelector) => {
                    const el = idOrSelector.startsWith('.') ? document.querySelector(idOrSelector) : document.getElementById(idOrSelector);
                    if (!el) return 'NOT_FOUND';
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    return {
                        idOrSelector,
                        width: rect.width,
                        height: rect.height,
                        top: rect.top,
                        left: rect.left,
                        display: style.display,
                        visibility: style.visibility,
                        opacity: style.opacity,
                        zIndex: style.zIndex
                    };
                };
                return {
                    page: getInfo('page-ai-analyst'),
                    chatPanel: getInfo('.ai-chat-panel'),
                    messages: getInfo('chat-messages'),
                    inputWrap: getInfo('.chat-input-wrap'),
                    chatInput: getInfo('chat-input'),
                    chatSend: getInfo('chat-send')
                };
            }""")
            print(f"\n[{label}] Elements state:")
            for name, info in details.items():
                print(f"  {name}: {info}")
        
        await check_input_rects("Before query")
        
        print("Sending chat query...")
        await page.fill("#chat-input", "What is the most critical threat right now?")
        await page.click("#chat-send")
        
        for i in range(1, 6):
            await asyncio.sleep(1)
            await check_input_rects(f"After query {i}s")
            
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
