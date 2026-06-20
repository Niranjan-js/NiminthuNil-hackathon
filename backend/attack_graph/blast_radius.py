from typing import Set, Dict, List, Any
from .graph_builder import AttackGraphBuilder

class BlastRadiusCalculator:
    def __init__(self, builder: AttackGraphBuilder):
        self.builder = builder

    def calculate_blast_radius(self, start_node: str, max_hops: int = 3) -> Dict[str, Any]:
        """Runs Breadth-First Search (BFS) to determine all compromised nodes reachable within N hops."""
        if start_node not in self.builder.nodes:
            return {"impacted_nodes": [], "critical_assets_compromised": 0}

        # Build adjacency
        adj: Dict[str, List[str]] = {node_id: [] for node_id in self.builder.nodes}
        for edge in self.builder.edges:
            if edge.source in adj:
                adj[edge.source].append(edge.target)

        visited: Set[str] = {start_node}
        queue = [(start_node, 0)]
        results = []
        critical_count = 0

        while queue:
            curr, depth = queue.pop(0)
            node_obj = self.builder.nodes[curr]
            
            if curr != start_node:
                results.append({
                    "id": curr,
                    "name": node_obj.name,
                    "type": node_obj.type,
                    "risk_score": node_obj.risk_score,
                    "hop_distance": depth
                })
                if node_obj.risk_score >= 80 or node_obj.type == "Critical Asset":
                    critical_count += 1

            if depth < max_hops:
                for neighbor in adj.get(curr, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, depth + 1))

        return {
            "impacted_nodes": results,
            "critical_assets_compromised": critical_count,
            "total_compromised_count": len(results)
        }
