import logging
import heapq
from typing import Dict, Any, List, Tuple, Set

logger = logging.getLogger("niravan.graphs.attack_graph")

class AttackGraph:
    """
    Live asset-seeded attack graph representation. Uses pure Python
    dictionaries to represent nodes and edges and implement graph algorithms.
    """

    @staticmethod
    def build_from_db(db) -> Dict[str, Any]:
        """
        Build a graph structure querying AssetModel, IOCModel, and IncidentModel.
        """
        try:
            from main import AssetModel, IOCModel, IncidentModel
            
            assets = db.query(AssetModel).all()
            iocs = db.query(IOCModel).all()
            incidents = db.query(IncidentModel).all()
            
            nodes = []
            edges = []
            
            # 1. Add Internet Node
            nodes.append({
                "id": "internet",
                "name": "External Internet",
                "type": "internet",
                "criticality": "low",
                "risk_score": 0
            })
            
            # 2. Add Assets
            for asset in assets:
                is_service = asset.type == "service" or asset.criticality == "critical" or "server" in asset.name.lower()
                nodes.append({
                    "id": asset.id,
                    "name": asset.name,
                    "type": "service" if is_service else "asset",
                    "criticality": asset.criticality or "medium",
                    "risk_score": asset.riskScore or 50
                })
                
            # 3. Add IOCs
            for ioc in iocs:
                nodes.append({
                    "id": f"ioc_{ioc.id}",
                    "name": ioc.indicator,
                    "type": "ioc",
                    "criticality": "high",
                    "risk_score": ioc.confidence or 80
                })
                
            # Connect Internet to internet-facing assets (e.g., DMZ, Web, Gateway, or first 2 assets)
            internet_facing = []
            for asset in assets:
                name_l = asset.name.lower()
                if any(x in name_l for x in ["web", "gateway", "dmz", "public", "external"]):
                    internet_facing.append(asset.id)
            
            # Fallback if none matches
            if not internet_facing and assets:
                internet_facing = [assets[0].id]
                if len(assets) > 1:
                    internet_facing.append(assets[1].id)
                    
            for target_id in internet_facing:
                edges.append({
                    "src": "internet",
                    "dst": target_id,
                    "weight": 0.2,  # Low resistance from internet to public assets
                    "relationship": "exposed_to"
                })
                
            # Connect assets sharing same subnet
            for i, a1 in enumerate(assets):
                for j, a2 in enumerate(assets):
                    if i >= j:
                        continue
                    
                    # If both have IPs and are in same /24 subnet
                    if a1.ip and a2.ip:
                        sub1 = ".".join(a1.ip.split(".")[:3])
                        sub2 = ".".join(a2.ip.split(".")[:3])
                        if sub1 == sub2:
                            # Edge resistance: lower riskScore means higher resistance (weight)
                            # Let's say weight is based on average risk score: higher risk score -> lower weight (easier to lateral move)
                            avg_risk = ((a1.riskScore or 50) + (a2.riskScore or 50)) / 2
                            weight = max(0.1, 1.0 - (avg_risk / 100.0))
                            
                            edges.append({
                                "src": a1.id,
                                "dst": a2.id,
                                "weight": weight,
                                "relationship": "lateral_movement"
                            })
                            edges.append({
                                "src": a2.id,
                                "dst": a1.id,
                                "weight": weight,
                                "relationship": "lateral_movement"
                            })
                            
            # Connect IOCs to assets that had incidents associated with them
            for incident in incidents:
                if not incident.host:
                    continue
                # Find asset matching incident host
                matching_asset = None
                for asset in assets:
                    if asset.name == incident.host or asset.ip == incident.host:
                        matching_asset = asset
                        break
                
                if matching_asset:
                    # Look up IOCs matching this incident (e.g. if description or technical details mentions an IOC)
                    for ioc in iocs:
                        if ioc.indicator in (incident.description or "") or (incident.technical and ioc.indicator in incident.technical):
                            edges.append({
                                "src": f"ioc_{ioc.id}",
                                "dst": matching_asset.id,
                                "weight": 0.1,  # Direct link, highly likely compromise
                                "relationship": "compromised_by"
                            })
                            
            logger.info(f"Built AttackGraph from DB: {len(nodes)} nodes, {len(edges)} edges")
            return {"nodes": nodes, "edges": edges}
        except Exception as e:
            logger.error(f"Error building AttackGraph: {e}")
            return {"nodes": [], "edges": []}

    @staticmethod
    def find_attack_path(graph: Dict[str, Any], src_id: str, dst_id: str) -> Dict[str, Any]:
        """
        Dijkstra's shortest path algorithm where edge weights represent resistance.
        Returns the path with the highest probability/lowest resistance.
        """
        nodes_list = graph.get("nodes", [])
        edges_list = graph.get("edges", [])
        
        # Resolve names to node IDs if necessary
        src_node_id = src_id
        dst_node_id = dst_id
        for node in nodes_list:
            if node["id"] == src_id or node["name"] == src_id:
                src_node_id = node["id"]
            if node["id"] == dst_id or node["name"] == dst_id:
                dst_node_id = node["id"]
        
        # Build adjacency list
        adj = {}
        for node in nodes_list:
            adj[node["id"]] = []
            
        for edge in edges_list:
            src = edge["src"]
            dst = edge["dst"]
            weight = edge["weight"]
            if src in adj and dst in adj:
                adj[src].append((dst, weight))
                
        # Dijkstra implementation
        distances = {node["id"]: float('inf') for node in nodes_list}
        previous = {node["id"]: None for node in nodes_list}
        
        if src_node_id not in distances or dst_node_id not in distances:
            return {
                "path": [],
                "cumulative_resistance": -1,
                "risk_score": 50
            }
            
        distances[src_node_id] = 0.0
        pq = [(0.0, src_node_id)]
        
        while pq:
            curr_dist, u = heapq.heappop(pq)
            
            if u == dst_node_id:
                break
                
            if curr_dist > distances[u]:
                continue
                
            for v, weight in adj.get(u, []):
                new_dist = curr_dist + weight
                if new_dist < distances[v]:
                    distances[v] = new_dist
                    previous[v] = u
                    heapq.heappush(pq, (new_dist, v))
                    
        # Reconstruct path
        path = []
        curr = dst_node_id
        if distances[dst_node_id] != float('inf'):
            while curr is not None:
                path.insert(0, curr)
                curr = previous[curr]
                
        # Convert path to nodes list with details
        detailed_path = []
        node_map = {n["id"]: n for n in nodes_list}
        for node_id in path:
            if node_id in node_map:
                detailed_path.append(node_map[node_id])
                
        # Risk score is inversely proportional to path distance (resistance)
        # Low resistance (distance) = high risk path
        risk_score = 100.0 if not path else max(0.0, 100.0 - (distances[dst_node_id] * 50))
        
        return {
            "path": detailed_path,
            "cumulative_resistance": distances[dst_node_id] if distances[dst_node_id] != float('inf') else -1,
            "risk_score": int(risk_score)
        }

    @classmethod
    def find_critical_paths(cls, graph: Dict[str, Any], db) -> List[Dict[str, Any]]:
        """
        Find top 3 most dangerous paths from internet-facing nodes to critical services.
        """
        nodes = graph.get("nodes", [])
        critical_services = [n["id"] for n in nodes if n["type"] == "service" and n["criticality"] == "critical"]
        
        paths = []
        for service_id in critical_services:
            res = cls.find_attack_path(graph, "internet", service_id)
            if res["path"] and len(res["path"]) > 1:
                paths.append(res)
                
        # Sort by risk score descending (highest risk first)
        paths.sort(key=lambda x: x["risk_score"], reverse=True)
        return paths[:3]

    @staticmethod
    def calculate_blast_radius(graph: Dict[str, Any], node_id: str) -> List[str]:
        """
        BFS traversal to find all reachable nodes within 3 hops.
        """
        nodes_list = graph.get("nodes", [])
        edges_list = graph.get("edges", [])
        
        # Build adjacency list
        adj = {}
        for node in nodes_list:
            adj[node["id"]] = []
            
        for edge in edges_list:
            src = edge["src"]
            dst = edge["dst"]
            if src in adj and dst in adj:
                adj[src].append(dst)
                
        if node_id not in adj:
            return []
            
        # BFS with depth tracking
        visited = {node_id}
        queue = [(node_id, 0)]
        blast_nodes = []
        
        while queue:
            curr_node, depth = queue.pop(0)
            
            if curr_node != node_id:
                blast_nodes.append(curr_node)
                
            if depth < 3:
                for neighbor in adj.get(curr_node, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, depth + 1))
                        
        return blast_nodes
