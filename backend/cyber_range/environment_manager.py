import time
from typing import List, Dict, Any

class RangeEnvironmentManager:
    @staticmethod
    def generate_syslog_logs() -> List[Dict[str, Any]]:
        """Generates mock background noise and attack logs in the range environment."""
        now = time.time()
        return [
            {"timestamp": now - 10, "source": "10.100.1.10", "message": "Nginx GET /index.html 200 OK", "type": "noise"},
            {"timestamp": now - 5, "source": "10.100.2.20", "message": "Alert: Unusual Modbus write packet to coil 5", "type": "alert"},
            {"timestamp": now, "source": "10.100.3.10", "message": "Syslog: Failed login attempt for user admin", "type": "alert"}
        ]
