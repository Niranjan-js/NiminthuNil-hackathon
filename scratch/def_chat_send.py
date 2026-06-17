import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Searching for definition of handleChatSend:")
for i, line in enumerate(lines):
    if 'function handleChatSend' in line or 'window.handleChatSend' in line:
        print(f"Line {i+1}: {line.strip()}")
