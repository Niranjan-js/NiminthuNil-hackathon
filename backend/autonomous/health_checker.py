import random
from typing import Dict, Any

class SystemHealthChecker:
    def __init__(self):
        self.simulate_outage = False

    def get_current_metrics(self) -> Dict[str, Any]:
        """Queries CPU, memory, API latency, and status codes."""
        # Simulated metrics
        cpu = random.randint(10, 45)
        mem = random.randint(30, 60)
        
        return {
            "cpu_pct": cpu,
            "mem_pct": mem,
            "api_latency_ms": random.randint(5, 50),
            "service_outage_detected": self.simulate_outage or cpu > 95 or mem > 98
        }
