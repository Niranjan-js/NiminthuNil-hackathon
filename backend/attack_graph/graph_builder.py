import json
from typing import Dict, List, Any

class AttackGraphNode:
    def __init__(self, node_id: str, name: str, node_type: str, risk_score: float = 50.0, properties: Dict[str, Any] = None):
        self.id = node_id
        self.name = name
        self.type = node_type  # User, Host, AD, Database, Critical Asset
        self.risk_score = risk_score
        self.properties = properties or {}

class AttackGraphEdge:
    def __init__(self, source: str, target: str, relationship: str, cvss: float = 0.0, difficulty: float = 1.0, properties: Dict[str, Any] = None):
        self.source = source
        self.target = target
        self.relationship = relationship  # USES, CONNECTS, EXPLOITS, TARGETS, INDICATES, CAN_REACH
        self.cvss = cvss
        self.difficulty = difficulty
        self.properties = properties or {}

class AttackGraphBuilder:
    def __init__(self):
        self.nodes: Dict[str, AttackGraphNode] = {}
        self.edges: List[AttackGraphEdge] = []

    def add_node(self, node_id: str, name: str, node_type: str, risk_score: float = 50.0, properties: Dict[str, Any] = None) -> AttackGraphNode:
        node = AttackGraphNode(node_id, name, node_type, risk_score, properties)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source: str, target: str, relationship: str, cvss: float = 0.0, difficulty: float = 1.0, properties: Dict[str, Any] = None) -> AttackGraphEdge:
        edge = AttackGraphEdge(source, target, relationship, cvss, difficulty, properties)
        self.edges.append(edge)
        return edge

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [{"id": n.id, "name": n.name, "type": n.type, "risk_score": n.risk_score, "properties": n.properties} for n in self.nodes.values()],
            "edges": [{"source": e.source, "target": e.target, "relationship": e.relationship, "cvss": e.cvss, "difficulty": e.difficulty, "properties": e.properties} for e in self.edges]
        }
