import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Incident API fetch in js/app.js:")
for i, line in enumerate(lines):
    if '/incidents' in line:
        print(f"Line {i+1}: {line.strip()}")
        # print 10 lines of context
        for j in range(1, 10):
            if i + j < len(lines):
                print(f"  +{j}: {lines[i+j].rstrip()}")
        print("-" * 40)
