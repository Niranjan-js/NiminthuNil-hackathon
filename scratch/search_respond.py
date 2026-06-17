import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('js/niravan.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Searching for respondQRI and respondDefault:")
for i, line in enumerate(lines):
    if 'respondQRI' in line or 'respondDefault' in line or 'respondRiskyAssets' in line:
        print(f"Line {i+1}: {line.strip()}")
