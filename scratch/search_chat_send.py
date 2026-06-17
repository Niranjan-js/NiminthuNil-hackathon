import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Line numbers of handleChatSend in js/app.js:")
for i, line in enumerate(lines):
    if 'handleChatSend' in line:
        print(f"Line {i+1}: {line.strip()}")
