import asyncio
import sys
from playwright.async_api import async_playwright

sys.stdout.reconfigure(encoding='utf-8')

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        console_messages = []
        page.on("console", lambda msg: console_messages.append(f"[{msg.type}] {msg.text}"))
        page.on("pageerror", lambda err: console_messages.append(f"[ERROR] {err.message}\n{err.stack}"))
        
        await page.goto("http://127.0.0.1:3000", wait_until="networkidle")
        await page.locator("text=admin@niravan.ai").click()
        await asyncio.sleep(4)
        
        await page.click("#nav-ai-analyst", force=True)
        await asyncio.sleep(2)
        
        async def log_state(step):
            state = await page.evaluate("""() => {
                const activePages = Array.from(document.querySelectorAll('.page')).map(p => ({
                    id: p.id,
                    active: p.classList.contains('active'),
                    visible: p.getBoundingClientRect().width > 0,
                    display: window.getComputedStyle(p).display
                }));
                const chatInput = document.getElementById('chat-input');
                return {
                    activePages: activePages.filter(p => p.active || p.visible),
                    inputVisible: chatInput ? (chatInput.getBoundingClientRect().width > 0) : 'NOT_FOUND',
                    inputDisabled: chatInput ? chatInput.disabled : 'NOT_FOUND',
                    url: window.location.href
                };
            }""")
            print(f"[{step}] State: {state}")
            
        await log_state("Before query")
        
        print("Sending chat query...")
        await page.fill("#chat-input", "What is the most critical threat right now?")
        await page.click("#chat-send")
        
        for i in range(1, 10):
            await asyncio.sleep(1)
            await log_state(f"After query {i}s")
            
        print("\n--- ALL Browser Console Logs ---")
        for msg in console_messages:
            print(msg)
        print("--------------------------------")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
