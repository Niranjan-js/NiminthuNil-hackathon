from typing import List, Dict, Any
from .atomic_runner import AtomicRunner

class MITRECampaignRunner:
    @staticmethod
    def run_apt29_campaign() -> Dict[str, Any]:
        """Runs a simulated multi-step campaign reflecting APT29 TTP steps."""
        steps = [
            {"technique_id": "T1566", "name": "Spearphishing Attachment", "phase": "Initial Access"},
            {"technique_id": "T1059.001", "name": "PowerShell Scripting", "phase": "Execution"},
            {"technique_id": "T1003.001", "name": "LSASS Memory Dump", "phase": "Credential Access"},
            {"technique_id": "T1041", "name": "Data Exfiltration Over C2 Channel", "phase": "Exfiltration"}
        ]

        results = []
        for s in steps:
            res = AtomicRunner.execute_test(s["technique_id"], s["name"])
            results.append({
                "phase": s["phase"],
                "technique_id": s["technique_id"],
                "name": s["name"],
                "status": res["status"],
                "logs": res["output_logs"]
            })

        return {
            "campaign": "APT29 Simulated Intrusion",
            "stages": len(results),
            "results": results
        }
