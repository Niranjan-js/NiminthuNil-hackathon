import sys

sys.stdout.reconfigure(encoding='utf-8')

# Find key areas in main.py we need to modify
with open('backend/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

targets = [
    'class VulnerabilityFindingModel',
    'openvas',
    'run_asm_scan_job',
    'def copilot_chat',
    'Plain-language Bilingual',
    'def sync_cisa_kev',
    '# ── API Endpoint',
    'class ScanJobModel',
    'class AssetModel',
    'ASMScanRequest',
    'BlockIPRequest',
]

for i, line in enumerate(lines):
    for t in targets:
        if t in line:
            print(f"Line {i+1}: {line.strip()[:120]}")
            break
