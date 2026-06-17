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
        await page.goto("http://127.0.0.1:3000", wait_until="networkidle")
        
        # Check login screen visibility
        is_visible_before = await page.locator("#login-screen").is_visible()
        print(f"Login screen visible before click: {is_visible_before}")
        
        # Click the Admin login quick-autofill
        print("Clicking Admin quick-autofill...")
        await page.locator("text=admin@niravan.ai").click()
        
        # Wait for API requests and DOM updates
        await asyncio.sleep(4)
        
        # Check login screen visibility again
        is_visible_after = await page.locator("#login-screen").is_visible()
        print(f"Login screen visible after click: {is_visible_after}")
        
        # Check local storage values
        storage = await page.evaluate("() => ({ token: localStorage.getItem('niravan_token'), email: localStorage.getItem('niravan_user_email'), role: localStorage.getItem('niravan_user_role') })")
        print("Local Storage values:")
        print(f"  Token: {storage['token']}")
        print(f"  Email: {storage['email']}")
        print(f"  Role:  {storage['role']}")
        
        # Check window.NIRAVAN_DATA events & assets count
        data_counts = await page.evaluate("() => ({ events: (window.NIRAVAN_DATA && window.NIRAVAN_DATA.events) ? window.NIRAVAN_DATA.events.length : null, assets: (window.NIRAVAN_DATA && window.NIRAVAN_DATA.assets) ? window.NIRAVAN_DATA.assets.length : null })")
        print("Window Data counts:")
        print(f"  Events: {data_counts['events']}")
        print(f"  Assets: {data_counts['assets']}")
        
        print("\n--- Browser Console Logs ---")
        for msg in console_messages:
            if "stats" in msg or "error" in msg.lower() or "log" in msg:
                print(msg)
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
