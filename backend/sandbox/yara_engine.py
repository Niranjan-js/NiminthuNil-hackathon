from typing import Dict, Any, List

class YaraEngine:
    def __init__(self):
        # Mocks a YARA database
        self.rules = {
            "Ransomware_Shadow_Delete": b"vssadmin.exe delete shadows",
            "Mimikatz_LSASS": b"sekurlsa::logonpasswords",
            "C2_Beacon_Signature": b"http://malicious.c2"
        }

    def scan_buffer(self, file_data: bytes) -> List[str]:
        """Scans the file buffer and returns a list of matched YARA rule names."""
        matches = []
        for name, pattern in self.rules.items():
            if pattern in file_data:
                matches.append(name)
        return matches
