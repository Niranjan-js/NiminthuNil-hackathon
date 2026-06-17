import sys
import re

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Fetch calls in js/app.js:")
for i, line in enumerate(lines):
    if 'fetch(' in line or 'fetch (' in line:
        print(f"Line {i+1}: {line.strip()}")
