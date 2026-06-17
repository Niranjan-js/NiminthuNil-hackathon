import sys
import re

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    js_content = f.read()

# Let's find functions or references related to guardian mode UI updates
matches = [m.start() for m in re.finditer(r'guardian', js_content, re.IGNORECASE)]
print(f"Found {len(matches)} occurrences of 'guardian' in js/app.js.")

# Find specific functions in js/app.js
for m in re.finditer(r'function\s+\w*guardian\w*|window\.\w*guardian\w*', js_content, re.IGNORECASE):
    print(f"Function match: {m.group(0)} at position {m.start()}")

# Let's find references to the threat panel element IDs
for element_id in ['guardian-threat-panel', 'gtp-explain', 'gtp-meta', 'gtp-raw-log']:
    matches = [m.start() for m in re.finditer(element_id, js_content)]
    print(f"Element ID '{element_id}' found {len(matches)} times.")
