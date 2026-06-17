import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Line numbers of getPlainEnglish in js/app.js:")
for i, line in enumerate(lines):
    if 'getPlainEnglish' in line:
        print(f"Line {i+1}: {line.strip()}")
