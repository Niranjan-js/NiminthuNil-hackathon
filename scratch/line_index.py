import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('index.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Line numbers of key elements in index.html:")
for i, line in enumerate(lines):
    if any(k in line for k in ['page-guardian', 'guardian-threat-panel', 'chat-messages', 'guardian-activity-feed', 'guardian-knowledge-grid']):
        print(f"Line {i+1}: {line.strip()}")
