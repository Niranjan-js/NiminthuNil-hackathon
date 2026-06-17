import re

with open('backend/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Analyzing backend/main.py for endpoints:")
for i, line in enumerate(lines):
    if '@app.' in line or '/api/v1' in line:
        print(f"Line {i+1}: {line.strip()}")
