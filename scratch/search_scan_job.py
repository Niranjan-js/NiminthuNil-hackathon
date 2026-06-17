import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('backend/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Searching for run_asm_scan_job in main.py:")
for i, line in enumerate(lines):
    if 'def run_asm_scan_job' in line:
        print(f"Line {i+1}: {line.strip()}")
        # print 40 lines of the function
        for j in range(1, 40):
            if i + j < len(lines):
                print(f"  +{j}: {lines[i+j].rstrip()}")
