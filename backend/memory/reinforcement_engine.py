from typing import Dict, Any

class ReinforcementLearningEngine:
    def __init__(self):
        # Maps playbook_name -> (successes, failures)
        self.playbook_stats: Dict[str, Any] = {
            "Isolate Host": [5, 0],
            "Block IP": [8, 1],
            "Reset Password": [3, 0],
            "Reboot Service": [2, 1]
        }

    def register_feedback(self, playbook_name: str, success: bool):
        """Reinforcement step: update success count based on analyst feedback."""
        if playbook_name not in self.playbook_stats:
            self.playbook_stats[playbook_name] = [0, 0]
        
        idx = 0 if success else 1
        self.playbook_stats[playbook_name][idx] += 1

    def get_playbook_success_rate(self, playbook_name: str) -> float:
        stats = self.playbook_stats.get(playbook_name, [1, 1])
        total = sum(stats)
        return round(stats[0] / total if total > 0 else 0.5, 3)
