from typing import List, Dict, Any

class GraphCommunityDetector:
    @staticmethod
    def detect_semantic_communities(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Groups graph nodes into isolated connected components or threat communities."""
        adj = {}
        for node in nodes:
            adj[node["id"]] = []

        for edge in edges:
            src = edge["source"]
            dst = edge["target"]
            if src in adj:
                adj[src].append(dst)
            if dst in adj:
                adj[dst].append(src)

        visited = set()
        communities = {}
        community_id = 0

        for node in nodes:
            n_id = node["id"]
            if n_id not in visited:
                # Run simple BFS to extract community
                curr_comp = []
                queue = [n_id]
                visited.add(n_id)
                while queue:
                    curr = queue.pop(0)
                    curr_comp.append(curr)
                    for neighbor in adj.get(curr, []):
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                communities[f"Community_{community_id}"] = curr_comp
                community_id += 1

        return communities
