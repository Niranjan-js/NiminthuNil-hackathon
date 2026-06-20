from typing import List, Dict, Any
from .graph_builder import AttackGraphBuilder

class PrivilegePathFinder:
    def __init__(self, builder: AttackGraphBuilder):
        self.builder = builder

    def find_privilege_escalation_paths(self, start_user: str) -> List[Dict[str, Any]]:
        escalations = []
        # Find paths where relationship is "HAS_PRIVILEGE", "MEMBER_OF"
        for edge in self.builder.edges:
            if edge.source == start_user and edge.relationship in ["HAS_PRIVILEGE", "MEMBER_OF"]:
                target_node = self.builder.nodes.get(edge.target)
                if target_node:
                    escalations.append({
                        "user": start_user,
                        "granted_identity": edge.target,
                        "identity_type": target_node.type,
                        "relationship": edge.relationship,
                        "escalation_level": "Domain Admin" if "admin" in edge.target.lower() else "Local Admin"
                    })
        return escalations
