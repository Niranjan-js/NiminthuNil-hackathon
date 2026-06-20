from typing import List, Dict, Any
from .graph_builder import AttackGraphBuilder

class LateralMovementSimulator:
    def __init__(self, builder: AttackGraphBuilder):
        self.builder = builder

    def simulate_lateral_steps(self, compromised_host: str) -> List[Dict[str, Any]]:
        """Finds possible immediate lateral hops (SMB, RDP, SSH, trust links) from a compromised host."""
        options = []
        for edge in self.builder.edges:
            if edge.source == compromised_host and edge.relationship in ["CONNECTS", "CAN_REACH", "TRUSTS"]:
                target_node = self.builder.nodes.get(edge.target)
                if target_node:
                    options.append({
                        "source": compromised_host,
                        "target": edge.target,
                        "target_name": target_node.name,
                        "target_type": target_node.type,
                        "protocol": edge.properties.get("protocol", "SMB"),
                        "difficulty": edge.difficulty,
                        "exploitability": round(edge.cvss / 10.0, 2) if edge.cvss > 0 else 0.1
                    })
        return options
