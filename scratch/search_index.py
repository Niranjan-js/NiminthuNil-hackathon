import re
import sys

# Reconfigure stdout to use utf-8
sys.stdout.reconfigure(encoding='utf-8')

with open('index.html', 'r', encoding='utf-8') as f:
    html = f.read()

print("Searching for elements with 'guardian' or 'copilot' or 'chat':")
# Let's search for any ID or class that matches
for m in re.finditer(r'id=["\']([a-zA-Z0-9_-]*(?:guardian|copilot|chat)[a-zA-Z0-9_-]*)["\']', html, re.IGNORECASE):
    print(f"ID: {m.group(1)} at position {m.start()}")
    # print context
    start = max(0, m.start() - 100)
    end = min(len(html), m.end() + 200)
    print("--- CONTEXT ---")
    print(html[start:end])
    print("----------------\n")
