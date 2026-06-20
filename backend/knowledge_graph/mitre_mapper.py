from typing import Dict, Any
from .neo4j_client import neo4j_client

class MITREGraphMapper:
    @staticmethod
    def map_technique_to_node(node_type: str, node_id: str, technique_id: str, tactic: str) -> Dict[str, Any]:
        """Binds a node (e.g. Asset, Incident) to a MITRE ATT&CK technique and tactic node."""
        tech_node_id = f"MITRE:{technique_id}"
        neo4j_client.add_node("MITRE_TTP", technique_id, f"MITRE {technique_id}", {"tactic": tactic})
        
        # Link entity to MITRE technique
        source_key = f"{node_type}:{node_id}"
        neo4j_client.add_relationship(source_key, f"MITRE_TTP:{technique_id}", "EXPLOITS")
        
        return {
            "mapped_entity": source_key,
            "technique": technique_id,
            "tactic": tactic
        }
