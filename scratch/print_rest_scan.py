import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('backend/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Rest of run_asm_scan_job:")
for i in range(2560, 2630):
    if i < len(lines):
        print(f"Line {i+1}: {lines[i].rstrip()}")
