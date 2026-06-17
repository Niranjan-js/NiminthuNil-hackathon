import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

print("Searching for '.cves' or 'cves' in JS files:")
for root, dirs, files in os.walk('js'):
    for file in files:
        if file.endswith('.js'):
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f):
                        if 'cves' in line.lower() or 'cve' in line.lower():
                            print(f"{path} Line {i+1}: {line.strip()}")
            except Exception as e:
                pass
