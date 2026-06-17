import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('backend/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Models in main.py:")
for i, line in enumerate(lines):
    if line.strip().startswith('class ') and '(Base)' in line:
        print(f"Line {i+1}: {line.strip()}")
