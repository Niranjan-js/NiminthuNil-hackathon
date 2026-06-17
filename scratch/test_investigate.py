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
        
        print("Logging in...")
        await page.locator("text=admin@niravan.ai").click()
        await asyncio.sleep(4)
        
        print("Navigating to NIRAVAN CORE...")
        await page.click("#nav-ai-analyst", force=True)
        await asyncio.sleep(2)
        
        async def print_pages_state(label):
            states = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('.page')).map(p => ({
                    id: p.id,
                    active: p.classList.contains('active'),
                    visible: p.getBoundingClientRect().width > 0,
                    display: window.getComputedStyle(p).display
                }));
            }""")
            print(f"[{label}] Pages:")
            for s in states:
                if s['active'] or s['visible']:
                    print(f"  - {s['id']}: active={s['active']}, visible={s['visible']}, display={s['display']}")
        
        await print_pages_state("Before query")
        
        print("Sending chat query...")
        await page.fill("#chat-input", "What is the most critical threat right now?")
        await page.click("#chat-send")
        
        for i in range(1, 6):
            await asyncio.sleep(1)
            await print_pages_state(f"After query {i}s")
            
        print("\n--- Browser Console Logs ---")
        for msg in console_messages:
            if "error" in msg.lower() or "navigate" in msg.lower() or "chat" in msg.lower():
                print(msg)
                
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
