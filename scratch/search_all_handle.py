import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

print("Searching for 'handleChatSend' in workspace files:")
for root, dirs, files in os.walk('.'):
    for file in files:
        if file.endswith('.js') or file.endswith('.html'):
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f):
                        if 'handleChatSend' in line:
                            print(f"{path} Line {i+1}: {line.strip()}")
            except Exception as e:
                pass
