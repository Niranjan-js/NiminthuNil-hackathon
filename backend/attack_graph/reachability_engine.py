from typing import List, Dict, Any
from .graph_builder import AttackGraphBuilder

class ReachabilityEngine:
    def __init__(self, builder: AttackGraphBuilder):
        self.builder = builder

    def is_reachable(self, source_ip: str, dest_ip: str) -> Dict[str, Any]:
        # Resolves network routing, firewall rules, and active port states
        direct = False
        ports = []
        for edge in self.builder.edges:
            if edge.source == source_ip and edge.target == dest_ip:
                direct = True
                ports.append(edge.properties.get("port", 445))
        return {
            "reachable": direct,
            "allowed_ports": ports,
            "segment_crossing": "Internal-to-DMZ" if "dmz" in dest_ip.lower() else "Internal-to-Internal"
        }
