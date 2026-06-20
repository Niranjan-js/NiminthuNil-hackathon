from typing import List, Dict, Any

class RangeAttackEmulator:
    @staticmethod
    def emulate_incident_scenario(scenario_name: str) -> List[Dict[str, Any]]:
        """Emulates a series of attacker actions across subnets for training."""
        steps = []
        if scenario_name == "Ransomware hospital lockdown":
            steps = [
                {"step": 1, "action": "Phishing email to vitals admin", "source": "198.51.100.5", "target": "10.100.2.15", "status": "compromised"},
                {"step": 2, "action": "Lateral movement attempt to vitals gateway", "source": "10.100.2.15", "target": "10.100.2.20", "status": "blocked_by_agent"},
                {"step": 3, "action": "Attempt to pivot to Collectorate database", "source": "10.100.2.15", "target": "10.100.1.20", "status": "blocked_by_segmentation"}
            ]
        else:
            steps = [
                {"step": 1, "action": "Port scanning local subnets", "source": "198.51.100.10", "target": "10.100.3.10", "status": "detected"}
            ]
        return steps
