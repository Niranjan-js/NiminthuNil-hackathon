import heapq
from typing import Dict, List, Any, Tuple
from .graph_builder import AttackGraphBuilder

class PathAnalyzer:
    def __init__(self, builder: AttackGraphBuilder):
        self.builder = builder

    def compute_edge_weight(self, cvss: float, difficulty: float, relationship: str) -> float:
        # Higher CVSS means easier exploit (lower weight). Higher difficulty means harder (higher weight).
        hop_cost = 1.0 if relationship in ["hosts", "connects"] else 2.0
        weight = max(0.05, difficulty + hop_cost - (cvss / 2.0))
        return weight

    def find_shortest_attack_path(self, start: str, end: str) -> Dict[str, Any]:
        if start not in self.builder.nodes or end not in self.builder.nodes:
            return {"status": "error", "message": f"Start '{start}' or End '{end}' node not found."}

        # Build adjacency list: node -> list of (target, weight, relationship)
        adj: Dict[str, List[Tuple[str, float, str]]] = {node_id: [] for node_id in self.builder.nodes}
        for edge in self.builder.edges:
            weight = self.compute_edge_weight(edge.cvss, edge.difficulty, edge.relationship)
            if edge.source in adj:
                adj[edge.source].append((edge.target, weight, edge.relationship))

        # Dijkstra algorithm: min-heap stores (total_weight, current_node, path_history, relationship_history)
        queue: List[Tuple[float, str, List[str], List[str]]] = [(0.0, start, [start], [])]
        visited: Dict[str, float] = {}

        while queue:
            weight, u, path, rels = heapq.heappop(queue)

            if u == end:
                probability = max(0.01, round(1.0 - (weight / 50.0), 3)) if weight < 50 else 0.01
                return {
                    "status": "success",
                    "path": path,
                    "relationships": rels,
                    "weight": round(weight, 3),
                    "probability": probability
                }

            if u in visited and visited[u] <= weight:
                continue
            visited[u] = weight

            for v, edge_w, rel in adj.get(u, []):
                if v not in visited or visited[v] > weight + edge_w:
                    heapq.heappush(queue, (weight + edge_w, v, path + [v], rels + [rel]))

        return {"status": "no_path", "message": "No privilege or network path links start and target nodes."}
