import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('backend/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Searching for traverse_attack_path and traverse_blast_radius:")
for i, line in enumerate(lines):
    if 'def traverse_attack_path' in line or 'def traverse_blast_radius' in line:
        print(f"Line {i+1}: {line.strip()}")
        # print 35 lines of context
        for j in range(1, 35):
            if i + j < len(lines):
                print(f"  +{j}: {lines[i+j].rstrip()}")
        print("-" * 40)
