from typing import List, Dict, Any

class VolatilityMockEngine:
    @staticmethod
    def run_pslist() -> List[Dict[str, Any]]:
        """Mocks the 'pslist' command output listing active memory processes."""
        return [
            {"pid": 4, "ppid": 0, "name": "System", "threads": 134},
            {"pid": 580, "ppid": 4, "name": "smss.exe", "threads": 4},
            {"pid": 4184, "ppid": 580, "name": "malicious_payload.exe", "threads": 18}
        ]

    @staticmethod
    def run_malfind() -> List[Dict[str, Any]]:
        """Mocks the 'malfind' command output flagging injected memory sections."""
        return [
            {
                "pid": 4184,
                "process_name": "malicious_payload.exe",
                "address": "0x000002696fc",
                "tag": "PAGE_EXECUTE_READWRITE",
                "notes": "Suspected process hollowing / DLL injection signature"
            }
        ]
