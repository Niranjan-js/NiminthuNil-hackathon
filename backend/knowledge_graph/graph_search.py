from typing import List, Dict, Any
from .neo4j_client import neo4j_client

class GraphSearcher:
    def __init__(self):
        self.client = neo4j_client

    def search_by_relationship(self, rel_type: str) -> List[Dict[str, Any]]:
        matched = []
        for src, dst, r_type, props in self.client._edges:
            if r_type == rel_type:
                matched.append({
                    "source": src,
                    "target": dst,
                    "relationship": r_type,
                    "properties": props
                })
        return matched

    def find_all_incidents_for_asset(self, asset_id: str) -> List[str]:
        incidents = []
        target_key = f"Asset:{asset_id}"
        for src, dst, r_type, props in self.client._edges:
            if dst == target_key and r_type == "TARGETS" and src.startswith("Incident:"):
                incidents.append(src.split(":", 1)[1])
        return incidents
