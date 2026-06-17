import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Searching for syncFromBackend in app.js:")
for i, line in enumerate(lines):
    if 'syncFromBackend' in line:
        print(f"Line {i+1}: {line.strip()}")
        # print 25 lines of context
        for j in range(1, 25):
            if i + j < len(lines):
                print(f"  +{j}: {lines[i+j].rstrip()}")
        print("-" * 40)
