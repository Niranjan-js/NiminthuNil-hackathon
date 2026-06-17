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
        
        # Click Admin quick-fill
        print("Logging in as Admin...")
        await page.locator("text=admin@niravan.ai").click()
        
        # Wait for data sync
        await asyncio.sleep(4)
        
        # Check login screen status
        is_visible = await page.locator("#login-screen").is_visible()
        print(f"Login screen visible: {is_visible}")
        if is_visible:
            print("Login failed, aborting.")
            await browser.close()
            return
            
        # Switch to NIRAVAN CORE page
        print("Navigating to NIRAVAN CORE (AI Analyst) page...")
        await page.click("#nav-ai-analyst")
        await asyncio.sleep(1) # wait for page transition
        
        # Send first query
        query1 = "What is the most critical threat right now?"
        print(f"Sending chat query: '{query1}'")
        await page.fill("#chat-input", query1)
        await page.click("#chat-send")
        
        # Wait for response
        await asyncio.sleep(3)
        
        # Send second query
        query2 = "Generate incident response playbook"
        print(f"Sending chat query: '{query2}'")
        await page.fill("#chat-input", query2)
        await page.click("#chat-send")
        
        # Wait for response
        await asyncio.sleep(3)

        # Send third query (Mentoring/general concept)
        query3 = "Explain brute force"
        print(f"Sending chat query: '{query3}'")
        await page.fill("#chat-input", query3)
        await page.click("#chat-send")
        
        # Wait for response
        await asyncio.sleep(3)
        
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
            if "error" in msg.lower():
                print(msg)
                
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
