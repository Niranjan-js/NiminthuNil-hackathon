from typing import Dict, Any

class TTPMapper:
    TTP_LIBRARY = {
        "kerberoasting": {"technique": "T1558.003", "tactic": "Credential Access"},
        "dcsync": {"technique": "T1003.006", "tactic": "Credential Access"},
        "vssadmin": {"technique": "T1490", "tactic": "Impact"},
        "powershell_download": {"technique": "T1059.001", "tactic": "Execution"}
    }

    @classmethod
    def get_ttp_details(cls, keyword: str) -> Dict[str, str]:
        return cls.TTP_LIBRARY.get(keyword.lower(), {"technique": "T1000", "tactic": "Defense Evasion"})
