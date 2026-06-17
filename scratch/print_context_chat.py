import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Context of handleChatSend:")
for i, line in enumerate(lines):
    if 'handleChatSend' in line:
        print(f"Line {i+1}: {line.strip()}")
        # print 10 lines after
        for j in range(1, 15):
            if i + j < len(lines):
                print(f"  +{j}: {lines[i+j].strip()}")
        print("-" * 40)
