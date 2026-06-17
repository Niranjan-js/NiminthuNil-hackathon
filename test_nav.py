import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        console_messages = []
        page.on("console", lambda msg: console_messages.append(f"[{msg.type}] {msg.text}"))
        page.on("pageerror", lambda err: console_messages.append(f"[ERROR] {err.message}\n{err.stack}"))
        
        await page.goto("http://127.0.0.1:3000", wait_until="networkidle")
        
        # Complete onboarding in local storage first to bypass setup wizard
        await page.evaluate("() => localStorage.setItem('NIRAVAN_ONBOARDED', 'true')")
        
        # Log in
        print("Logging in...")
        await page.locator("text=admin@niravan.ai").click()
        await asyncio.sleep(5)
        
        # Get active pages
        active_pages = await page.evaluate("() => Array.from(document.querySelectorAll('.page')).map(p => ({ id: p.id, classes: p.className, visible: p.getBoundingClientRect().width > 0 }))")
        print("Pages before navigation:", active_pages)
        
        # Click NIRAVAN CORE
        print("Clicking nav-ai-analyst...")
        await page.click("#nav-ai-analyst", force=True)
        await asyncio.sleep(2)
        
        # Get active pages again
        active_pages_after = await page.evaluate("() => Array.from(document.querySelectorAll('.page')).map(p => ({ id: p.id, classes: p.className, visible: p.getBoundingClientRect().width > 0, displayStyle: window.getComputedStyle(p).display }))")
        print("Pages after navigation:", active_pages_after)
        
        # Check chat-input details
        input_details = await page.evaluate("() => { const el = document.getElementById('chat-input'); if (!el) return 'Not found'; return { visible: el.getBoundingClientRect().width > 0, classes: el.className, display: window.getComputedStyle(el).display, parentDisplay: window.getComputedStyle(el.parentElement).display, pageDisplay: window.getComputedStyle(document.getElementById('page-ai-analyst')).display }; }")
        print("Chat input details:", input_details)
        
        print("\n--- Console Logs ---")
        for msg in console_messages:
            print(msg)
            
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
