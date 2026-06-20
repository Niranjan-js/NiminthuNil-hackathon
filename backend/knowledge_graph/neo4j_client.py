import re
from typing import Dict, List, Any, Tuple

class MockNeo4jClient:
    def __init__(self):
        self._nodes: Dict[str, Dict[str, Any]] = {}  # key -> attributes
        self._edges: List[Tuple[str, str, str, Dict[str, Any]]] = []  # (src, dst, type, props)

    def add_node(self, label: str, node_id: str, name: str, properties: Dict[str, Any] = None) -> Dict[str, Any]:
        node_key = f"{label}:{node_id}"
        self._nodes[node_key] = {
            "label": label,
            "id": node_id,
            "name": name,
            "properties": properties or {}
        }
        return self._nodes[node_key]

    def add_relationship(self, source_key: str, target_key: str, rel_type: str, properties: Dict[str, Any] = None):
        self._edges.append((source_key, target_key, rel_type, properties or {}))

    def execute_cypher(self, query: str) -> List[Dict[str, Any]]:
        # Mock simple cypher parser. e.g. MATCH (n:Asset) RETURN n
        results = []
        if "MATCH (n:Asset)" in query:
            for key, val in self._nodes.items():
                if val["label"] == "Asset":
                    results.append({"n": val})
        elif "MATCH (i:Incident)" in query:
            for key, val in self._nodes.items():
                if val["label"] == "Incident":
                    results.append({"i": val})
        else:
            # return everything
            for key, val in self._nodes.items():
                results.append({"node": val})
        return results

    def clear(self):
        self._nodes.clear()
        self._edges.clear()

neo4j_client = MockNeo4jClient()
