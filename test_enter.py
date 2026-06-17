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
        
        # Inject script to hook navigateTo on page load
        await page.add_init_script("""
            const checkAndHook = () => {
                if (window.navigateTo && !window.navigateTo.__hooked) {
                    const orig = window.navigateTo;
                    window.navigateTo = function(pageName) {
                        console.log("[HOOK] navigateTo called with: " + pageName + "\\nStack:\\n" + new Error().stack);
                        orig(pageName);
                    };
                    window.navigateTo.__hooked = true;
                }
            };
            // Hook periodically to ensure we catch it
            setInterval(checkAndHook, 50);
        """)
        
        await page.goto("http://127.0.0.1:3000", wait_until="networkidle")
        await page.locator("text=admin@niravan.ai").click()
        await asyncio.sleep(4)
        
        await page.click("#nav-ai-analyst", force=True)
        await asyncio.sleep(2)
        
        print("Filling query...")
        await page.fill("#chat-input", "What is the most critical threat right now?")
        
        print("Pressing Enter...")
        await page.press("#chat-input", "Enter")
        
        await asyncio.sleep(4)
        
        print("\n--- Browser Console Logs ---")
        for msg in console_messages:
            if "[HOOK]" in msg or "navigateTo" in msg or "stats" in msg or "error" in msg.lower():
                print(msg)
        print("----------------------------")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
