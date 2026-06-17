import os
import sys

# Configure output to avoid encoding crashes
sys.stdout.reconfigure(encoding='utf-8')

js_dir = 'js'
for f in os.listdir(js_dir):
    if f.endswith('.js'):
        path = os.path.join(js_dir, f)
        with open(path, 'r', encoding='utf-8', errors='ignore') as file:
            for i, line in enumerate(file, 1):
                if 'setInterval' in line or 'setTimeout' in line:
                    print(f"{f}:{i}: {line.strip()[:120]}")
