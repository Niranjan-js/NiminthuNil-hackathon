import sys
import re

sys.stdout.reconfigure(encoding='utf-8')

# Search for /api/v1 or fetch calls in JS files
js_files = ['js/app.js', 'js/niravan.js']
for file_path in js_files:
    with open(file_path, 'r', encoding='utf-8') as f:
        js_content = f.read()
    
    # find fetch or api calls
    fetches = [m.start() for m in re.finditer(r'fetch\s*\(', js_content)]
    print(f"File {file_path} has {len(fetches)} fetch() calls.")
    for m in re.finditer(r'fetch\s*\(\s*[\'`"]/api/v1/([a-zA-Z0-9_-]+)(?:/[a-zA-Z0-9_-]+)*[\'`"]', js_content):
        print(f"  API: {m.group(0)}")
