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
            is_visible = await page.locator("#chat-input").is_visible()
            active_page = await page.evaluate("() => Array.from(document.querySelectorAll('.page')).find(p => p.classList.contains('active'))?.id")
            print(f"Step 0 (Before query) - Is input visible: {is_visible}, Active page: {active_page}")
            
            # Send first query
            query1 = "What is the most critical threat right now?"
            print(f"Sending chat query 1: '{query1}'")
            await page.fill("#chat-input", query1)
            await page.press("#chat-input", "Enter")
            
            # Wait for response
            await asyncio.sleep(4)
            is_visible = await page.locator("#chat-input").is_visible()
            active_page = await page.evaluate("() => Array.from(document.querySelectorAll('.page')).find(p => p.classList.contains('active'))?.id")
            print(f"Step 1 (After query 1) - Is input visible: {is_visible}, Active page: {active_page}")
            
            # Send second query
            query2 = "Generate incident response playbook"
            print(f"Sending chat query 2: '{query2}'")
            await page.fill("#chat-input", query2)
            await page.press("#chat-input", "Enter")
            
            # Wait for response
            await asyncio.sleep(4)
            is_visible = await page.locator("#chat-input").is_visible()
            active_page = await page.evaluate("() => Array.from(document.querySelectorAll('.page')).find(p => p.classList.contains('active'))?.id")
            print(f"Step 2 (After query 2) - Is input visible: {is_visible}, Active page: {active_page}")
            
        except Exception as e:
            print(f"Exception encountered: {e}")
        finally:
            print(f"Final URL: {page.url}")
            is_login_visible = await page.locator("#login-screen").is_visible()
            print(f"Is login screen visible: {is_login_visible}")
            
            # Dump all messages in the chat panel
            print("\n--- Chat Transcript ---")
            messages = await page.locator("#chat-messages .message").all()
            for idx, msg in enumerate(messages, 1):
                role = "User" if "user-msg" in (await msg.get_attribute("class")) else "NIRAVAN AI"
                content_elem = msg.locator(".msg-content")
                content = await content_elem.inner_text() if await content_elem.count() > 0 else await msg.inner_text()
                print(f"[{role}]: {content.strip()}")
                print("-" * 30)

            print("\n--- Browser Console Logs ---")
            for msg in console_messages:
                print(msg)
            print("----------------------------")
            
            await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
