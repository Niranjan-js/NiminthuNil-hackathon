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
        
        try:
            print("Navigating to http://127.0.0.1:3000...")
            await page.goto("http://127.0.0.1:3000", wait_until="networkidle")
            
            # Click Admin quick-fill
            print("Logging in as Admin...")
            await page.locator("text=admin@niravan.ai").click()
            await asyncio.sleep(4)
            
            # Switch to NIRAVAN CORE page
            print("Navigating to NIRAVAN CORE (AI Analyst)...")
            await page.click("#nav-ai-analyst", force=True)
            await asyncio.sleep(2)
            
            # Check visibility of chat-input
            is_input_visible = await page.locator("#chat-input").is_visible()
            active_page = await page.evaluate("() => Array.from(document.querySelectorAll('.page')).find(p => p.classList.contains('active'))?.id")
            print(f"Before query - Is input visible: {is_input_visible}, Active page: {active_page}")
            
            # Send first query
            query1 = "What is the most critical threat right now?"
            print(f"Sending chat query: '{query1}'")
            await page.fill("#chat-input", query1)
            await page.click("#chat-send")
            
            # Wait 1 second
            await asyncio.sleep(1)
            is_input_visible_during = await page.locator("#chat-input").is_visible()
            active_page_during = await page.evaluate("() => Array.from(document.querySelectorAll('.page')).find(p => p.classList.contains('active'))?.id")
            print(f"During query - Is input visible: {is_input_visible_during}, Active page: {active_page_during}")
            
            # Wait 4 seconds for response
            await asyncio.sleep(4)
            is_input_visible_after = await page.locator("#chat-input").is_visible()
            active_page_after = await page.evaluate("() => Array.from(document.querySelectorAll('.page')).find(p => p.classList.contains('active'))?.id")
            print(f"After query - Is input visible: {is_input_visible_after}, Active page: {active_page_after}")
            
        except Exception as e:
            print(f"Exception encountered: {e}")
        finally:
            print(f"Final URL: {page.url}")
            is_login_visible = await page.locator("#login-screen").is_visible()
            print(f"Is login screen visible: {is_login_visible}")
            
            print("\n--- Browser Console Logs ---")
            for msg in console_messages:
                print(msg)
            print("----------------------------")
            
            await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
