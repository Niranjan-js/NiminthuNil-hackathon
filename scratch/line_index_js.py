import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print("Line numbers of key guardian functions in js/app.js:")
for i, line in enumerate(lines):
    if any(k in line for k in ['function renderGuardianMode', 'function updateGuardianRing', 'function renderGuardianCards', 'function addGuardianActivity', 'function guardianBlockThreat', 'function guardianNotifyIT', 'function guardianMarkSafe', 'window.toggleGuardianAdvancedView']):
        print(f"Line {i+1}: {line.strip()}")
