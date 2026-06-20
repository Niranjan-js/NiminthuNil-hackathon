from typing import Dict, Any
from .topology_builder import CyberRangeTopologyBuilder
from .attack_emulator import RangeAttackEmulator

class RangeScenarioRunner:
    @staticmethod
    def run_training_scenario(scenario_name: str) -> Dict[str, Any]:
        """Runs the complete scenario, loading topology, and emulating attack steps."""
        topology = CyberRangeTopologyBuilder.build_district_topology()
        attack_steps = RangeAttackEmulator.emulate_incident_scenario(scenario_name)

        # Count successful deflections
        deflected = sum(1 for step in attack_steps if "blocked" in step["status"])

        return {
            "scenario": scenario_name,
            "topology_used": topology["name"],
            "total_attack_steps": len(attack_steps),
            "deflected_attacks": deflected,
            "readiness_score": round((deflected / max(1, len(attack_steps))) * 100.0, 2),
            "step_by_step_report": attack_steps
        }
