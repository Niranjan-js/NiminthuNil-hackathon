import collections
import heapq
from typing import List, Dict, Any, Optional

class GraphNode:
    def __init__(self, node_id: str, name: str, node_type: str, risk_score: float = 0.0):
        self.id = node_id
        self.name = name
        self.type = node_type # Asset, User, Credential, Service, Vulnerability
        self.risk = risk_score

class GraphEdge:
    def __init__(self, source: str, target: str, relationship: str, cvss: float = 0.0, difficulty: float = 1.0):
        self.source = source
        self.target = target
        self.relationship = relationship # can_reach, hosts, exploits, authenticates
        self.cvss = cvss
        self.difficulty = difficulty

class AttackGraphSolver:
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        # adjacency list: source -> list of (target, edge_weight, relationship)
        self.adj: Dict[str, List[Any]] = collections.defaultdict(list)

    def add_node(self, node_id: str, name: str, node_type: str, risk: float = 0.0):
        self.nodes[node_id] = GraphNode(node_id, name, node_type, risk)

    def add_edge(self, source: str, target: str, relationship: str, cvss: float = 0.0, difficulty: float = 1.0):
        """Calculates Dijkstra edge weight:
        weight = difficulty + hop - (CVSS / 2)
        """
        hop_weight = 1.0 if relationship == "hosts" else 2.0
        weight = max(0.1, difficulty + hop_weight - (cvss / 2.0))
        
        self.adj[source].append((target, weight, relationship, cvss))

    def solve_shortest_attack_path(self, start: str, end: str) -> Dict[str, Any]:
        """Calculates the easiest exploit path using Dijkstra's algorithm."""
        if start not in self.nodes or end not in self.nodes:
            return {"status": "error", "message": "Start or end node not found in attack graph"}

        # min-priority queue: (cost, current_node, path_history)
        pq = [(0.0, start, [start])]
        visited = {}

        while pq:
            cost, u, path = heapq.heappop(pq)

            if u == end:
                return {
                    "status": "success",
                    "path": path,
                    "cost": round(cost, 2),
                    "probability": round(max(0.1, 1.0 - (cost / 40.0)), 2) # closer to 0 cost = 1.0 probability
                }

            if u in visited and visited[u] <= cost:
                continue
            visited[u] = cost

            for v, weight, rel, cvss in self.adj[u]:
                if v not in visited or visited[v] > cost + weight:
                    heapq.heappush(pq, (cost + weight, v, path + [v]))

        return {"status": "no_path", "message": "No attack path found linking nodes"}

    def calculate_blast_radius(self, start_node: str, steps: int = 2) -> List[str]:
        """Performs BFS search to determine potential blast radius (reachability) within N steps."""
        if start_node not in self.nodes:
            return []

        visited = {start_node}
        queue = collections.deque([(start_node, 0)])
        blast_radius_nodes = []

        while queue:
            u, d = queue.popleft()
            if d > 0:
                blast_radius_nodes.append(u)
            if d >= steps:
                continue

            for v, _, _, _ in self.adj[u]:
                if v not in visited:
                    visited.add(v)
                    queue.append((v, d + 1))

        return blast_radius_nodes
