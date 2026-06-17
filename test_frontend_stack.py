import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        console_messages = []
        page.on("console", lambda msg: console_messages.append(f"[{msg.type}] {msg.text}"))
        page.on("pageerror", lambda err: console_messages.append(f"[ERROR] {err.message}\n{err.stack}"))
        
        print("Navigating to http://127.0.0.1:3000...")
        try:
            await page.goto("http://127.0.0.1:3000", wait_until="networkidle")
        except Exception as e:
            print(f"Error navigating: {e}")
            await browser.close()
            return

        print("Page loaded. Active URL:", page.url)
        
        # Try to find the admin login quick-fill option and click it
        print("Clicking Admin quick-autofill...")
        try:
            admin_btn = page.locator("text=admin@niravan.ai")
            await admin_btn.click()
            print("Clicked admin quick-fill.")
        except Exception as e:
            print(f"Failed to click admin quick-fill: {e}")
            
        await asyncio.sleep(4)
        
        print("\n--- Browser Console Logs & Stack Traces ---")
        for msg in console_messages:
            print(msg)
            print("-" * 40)
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
