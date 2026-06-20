from typing import Dict, List, Any

class CoverageMapper:
    @staticmethod
    def map_detection_coverage(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Maps active Wazuh/Correlation rules to a coverage percentage list by MITRE Tactic."""
        tactics = {
            "Initial Access": 0,
            "Execution": 0,
            "Persistence": 0,
            "Privilege Escalation": 0,
            "Credential Access": 0,
            "Discovery": 0,
            "Lateral Movement": 0,
            "Collection": 0,
            "Command and Control": 0,
            "Exfiltration": 0,
            "Impact": 0
        }

        # Scan rules and increment coverage counts
        for rule in rules:
            mitre_str = rule.get("mitre", "")
            for tactic in tactics.keys():
                if tactic.lower().replace(" ", "") in mitre_str.lower().replace(" ", ""):
                    tactics[tactic] += 1

        total_rules = len(rules)
        coverage_percentages = {}
        for tactic, count in tactics.items():
            coverage_percentages[tactic] = round((count / max(1, total_rules)) * 100.0, 2)

        return {
            "total_monitored_rules": total_rules,
            "tactic_coverage_counts": tactics,
            "tactic_coverage_percentages": coverage_percentages
        }
