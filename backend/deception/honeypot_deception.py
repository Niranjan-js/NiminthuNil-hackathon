import time
from typing import Dict, Any, List

class DeceptionManager:
    @staticmethod
    def generate_honeypot_hits() -> List[Dict[str, Any]]:
        """Mocks high-interaction deception triggers from Cowrie (SSH) and Conpot (Modbus)."""
        now = time.time()
        return [
            {
                "timestamp": now - 15,
                "honeypot_name": "cowrie-ssh-primary",
                "type": "SSH",
                "source_ip": "185.220.101.47",
                "attacker_input": "admin / admin123",
                "message": "SSH Login Attempt Failed"
            },
            {
                "timestamp": now,
                "honeypot_name": "conpot-modbus-substation",
                "type": "Modbus",
                "source_ip": "91.240.118.12",
                "attacker_input": "Read coils [0..100]",
                "message": "ICS Register Scan Detected"
            }
        ]
