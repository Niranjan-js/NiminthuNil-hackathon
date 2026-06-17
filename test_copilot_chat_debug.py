import asyncio
from playwright.async_api import async_playwright

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
            
            # Wait for data sync
            await asyncio.sleep(4)
            
            # Switch to NIRAVAN CORE page
            print("Navigating to NIRAVAN CORE (AI Analyst)...")
            await page.click("#nav-ai-analyst")
            await asyncio.sleep(1)
            
            # Send first query
            query1 = "What is the most critical threat right now?"
            print(f"Sending chat query: '{query1}'")
            await page.fill("#chat-input", query1)
            await page.click("#chat-send")
            
            # Wait for response
            await asyncio.sleep(4)
            
            # Send second query
            query2 = "Generate incident response playbook"
            print(f"Sending chat query: '{query2}'")
            await page.fill("#chat-input", query2)
            await page.click("#chat-send")
            
            # Wait for response
            await asyncio.sleep(4)
            
        except Exception as e:
            print(f"Exception encountered: {e}")
        finally:
            print(f"Final URL: {page.url}")
            is_login_visible = await page.locator("#login-screen").is_visible()
            print(f"Is login screen visible: {is_login_visible}")
            
            # Check window.NIRAVAN_DATA
            data_counts = await page.evaluate("() => { try { return { active: window.NIRAVAN_API_ACTIVE, events: window.NIRAVAN_DATA.events.length, token: !!localStorage.getItem('niravan_token') }; } catch (e) { return { error: e.message }; } }")
            print(f"Window Data Stats: {data_counts}")

            print("\n--- Browser Console Logs ---")
            for msg in console_messages:
                print(msg)
            print("----------------------------")
            
            await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
