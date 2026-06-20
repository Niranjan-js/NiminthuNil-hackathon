import logging
import json
from typing import Dict, Any, List, Set

logger = logging.getLogger("niravan.graphs.knowledge_graph")

class KnowledgeGraph:
    """
    Dynamic entity relationship knowledge graph mapping Users, Assets, IOCs, Incidents,
    and Vulnerabilities, with BFS context retrieval and attack chain reconstruction.
    """

    def __init__(self, db):
        self.db = db

    def build_graph(self) -> Dict[str, Any]:
        """
        Query GraphNodeModel and GraphEdgeModel. If empty, seed from main relational tables.
        """
        try:
            from main import GraphNodeModel, GraphEdgeModel
            
            nodes = self.db.query(GraphNodeModel).all()
            edges = self.db.query(GraphEdgeModel).all()
            
            if not nodes:
                # Seed graph nodes and edges from relational tables
                self._seed_graph_from_db()
                nodes = self.db.query(GraphNodeModel).all()
                edges = self.db.query(GraphEdgeModel).all()
                
            nodes_list = []
            for n in nodes:
                try:
                    props = json.loads(n.properties) if n.properties else {}
                except Exception:
                    props = {}
                nodes_list.append({
                    "id": n.entity_id,
                    "type": n.entity_type,
                    "name": n.name,
                    "risk_weight": n.risk_weight,
                    "properties": props
                })
                
            edges_list = []
            for e in edges:
                try:
                    props = json.loads(e.properties) if e.properties else {}
                except Exception:
                    props = {}
                edges_list.append({
                    "src": e.source_id,
                    "src_type": e.source_type,
                    "dst": e.target_id,
                    "dst_type": e.target_type,
                    "relationship": e.relationship,
                    "weight": e.weight,
                    "properties": props
                })
                
            return {"nodes": nodes_list, "edges": edges_list}
        except Exception as e:
            logger.error(f"Error building KnowledgeGraph: {e}")
            return {"nodes": [], "edges": []}

    def _seed_graph_from_db(self):
        """Helper to seed the graph tables from the existing main database tables."""
        try:
            from main import UserModel, AssetModel, IOCModel, IncidentModel, CVEModel
            
            logger.info("Seeding knowledge graph tables from relational models...")
            
            # Users
            users = self.db.query(UserModel).all()
            for u in users:
                self.add_entity("User", u.email, {"name": u.username, "role": u.role, "department": u.department})
                
            # Assets
            assets = self.db.query(AssetModel).all()
            for a in assets:
                self.add_entity("Asset", a.id, {"name": a.name, "ip": a.ip, "type": a.type, "criticality": a.criticality})
                if a.owner:
                    # Find user by email or name to link
                    user = self.db.query(UserModel).filter(
                        (UserModel.email == a.owner) | (UserModel.username == a.owner)
                    ).first()
                    if user:
                        self.add_relationship(user.email, "User", a.id, "Asset", "owns")
                        
            # IOCs
            iocs = self.db.query(IOCModel).all()
            for ioc in iocs:
                self.add_entity("IOC", ioc.indicator, {"type": ioc.type, "threat": ioc.threat, "confidence": ioc.confidence})
                
            # Incidents
            incidents = self.db.query(IncidentModel).all()
            for inc in incidents:
                self.add_entity("Incident", inc.id, {"title": inc.title, "severity": inc.severity, "type": inc.type})
                
                # Link incident to asset if host matches
                if inc.host:
                    asset = self.db.query(AssetModel).filter(
                        (AssetModel.name == inc.host) | (AssetModel.ip == inc.host)
                    ).first()
                    if asset:
                        self.add_relationship(inc.id, "Incident", asset.id, "Asset", "targets")
                        
                # Link incident to user if user matches
                if inc.user:
                    user = self.db.query(UserModel).filter(
                        (UserModel.email == inc.user) | (UserModel.username == inc.user)
                    ).first()
                    if user:
                        self.add_relationship(user.email, "User", inc.id, "Incident", "triggers")
                        
            # CVEs (Vulnerabilities)
            cves = self.db.query(CVEModel).all()
            for cve in cves:
                self.add_entity("Vulnerability", cve.id, {"score": cve.score, "severity": cve.severity, "desc": cve.desc})
                
                # Link CVE to asset if affected matches
                if cve.affected:
                    asset = self.db.query(AssetModel).filter(
                        (AssetModel.name == cve.affected) | (AssetModel.ip == cve.affected)
                    ).first()
                    if asset:
                        self.add_relationship(asset.id, "Asset", cve.id, "Vulnerability", "exploited_by")
                        
            self.db.commit()
            logger.info("Successfully seeded knowledge graph.")
        except Exception as e:
            logger.error(f"Error seeding knowledge graph: {e}")

    def add_entity(self, entity_type: str, entity_id: str, properties: Dict[str, Any] = None) -> bool:
        """Add or update an entity in the graph database."""
        try:
            from main import GraphNodeModel
            
            # Check if exists
            node = self.db.query(GraphNodeModel).filter(
                GraphNodeModel.entity_type == entity_type,
                GraphNodeModel.entity_id == entity_id
            ).first()
            
            props_str = json.dumps(properties or {})
            
            if node:
                node.properties = props_str
                if properties and "name" in properties:
                    node.name = properties["name"]
            else:
                name = properties.get("name", entity_id) if properties else entity_id
                node = GraphNodeModel(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    name=name,
                    properties=props_str
                )
                self.db.add(node)
                
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Error adding entity to KnowledgeGraph: {e}")
            return False

    def add_relationship(self, src_id: str, src_type: str, dst_id: str, dst_type: str, relationship: str, weight: float = 1.0, properties: Dict[str, Any] = None) -> bool:
        """Create or update a relationship (directed edge) in the graph database."""
        try:
            from main import GraphEdgeModel
            
            edge = self.db.query(GraphEdgeModel).filter(
                GraphEdgeModel.source_id == src_id,
                GraphEdgeModel.source_type == src_type,
                GraphEdgeModel.target_id == dst_id,
                GraphEdgeModel.target_type == dst_type,
                GraphEdgeModel.relationship == relationship
            ).first()
            
            props_str = json.dumps(properties or {})
            
            if edge:
                edge.properties = props_str
                edge.weight = weight
            else:
                edge = GraphEdgeModel(
                    source_type=src_type,
                    source_id=src_id,
                    target_type=dst_type,
                    target_id=dst_id,
                    relationship=relationship,
                    weight=weight,
                    properties=props_str
                )
                self.db.add(edge)
                
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Error adding relationship to KnowledgeGraph: {e}")
            return False

    def get_entity_context(self, entity_id: str) -> Dict[str, Any]:
        """Get all directly connected nodes and edges for a given entity."""
        try:
            graph = self.build_graph()
            nodes = graph.get("nodes", [])
            edges = graph.get("edges", [])
            
            # Find the starting node
            entity_node = next((n for n in nodes if n["id"] == entity_id), None)
            if not entity_node:
                return {"entity": None, "connections": []}
                
            connections = []
            for edge in edges:
                if edge["src"] == entity_id:
                    target_node = next((n for n in nodes if n["id"] == edge["dst"]), None)
                    if target_node:
                        connections.append({
                            "direction": "out",
                            "relationship": edge["relationship"],
                            "node": target_node
                        })
                elif edge["dst"] == entity_id:
                    source_node = next((n for n in nodes if n["id"] == edge["src"]), None)
                    if source_node:
                        connections.append({
                            "direction": "in",
                            "relationship": edge["relationship"],
                            "node": source_node
                        })
                        
            return {
                "entity": entity_node,
                "connections": connections
            }
        except Exception as e:
            logger.error(f"Error getting entity context: {e}")
            return {"entity": None, "connections": []}

    def find_connected_threats(self, entity_id: str, depth: int = 2) -> List[Dict[str, Any]]:
        """BFS search finding all threat entities (IOCs, Incidents) within N hops."""
        try:
            graph = self.build_graph()
            nodes = graph.get("nodes", [])
            edges = graph.get("edges", [])
            
            # Build adjacency list
            adj = {}
            node_map = {}
            for node in nodes:
                adj[node["id"]] = []
                node_map[node["id"]] = node
                
            for edge in edges:
                src = edge["src"]
                dst = edge["dst"]
                if src in adj and dst in adj:
                    adj[src].append(dst)
                    adj[dst].append(src)  # treat as undirected for threat tracing
                    
            if entity_id not in adj:
                return []
                
            visited = {entity_id}
            queue = [(entity_id, 0)]
            threats = []
            
            while queue:
                curr, curr_depth = queue.pop(0)
                
                if curr != entity_id:
                    node = node_map[curr]
                    if node["type"] in ["IOC", "Incident", "Vulnerability"]:
                        threats.append({
                            "distance": curr_depth,
                            "node": node
                        })
                        
                if curr_depth < depth:
                    for neighbor in adj.get(curr, []):
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append((neighbor, curr_depth + 1))
                            
            return threats
        except Exception as e:
            logger.error(f"Error finding connected threats: {e}")
            return []

    def get_attack_chain(self, incident_id: str) -> Dict[str, Any]:
        """
        Reconstruct the full attack chain for an incident by tracing entity relationships.
        e.g. Incident -> targets Asset -> has Vulnerability -> exploited_by Threat
        """
        try:
            graph = self.build_graph()
            nodes = graph.get("nodes", [])
            edges = graph.get("edges", [])
            
            node_map = {n["id"]: n for n in nodes}
            
            incident = node_map.get(incident_id)
            if not incident or incident["type"] != "Incident":
                return {"chain": [], "timeline": []}
                
            chain = [incident]
            timeline = [f"Detection of incident: {incident['name']}"]
            
            # 1. Find assets targeted by the incident
            targeted_assets = []
            for edge in edges:
                if edge["src"] == incident_id and edge["relationship"] == "targets" and edge["dst_type"] == "Asset":
                    asset = node_map.get(edge["dst"])
                    if asset:
                        targeted_assets.append(asset)
                        
            for asset in targeted_assets:
                chain.append(asset)
                timeline.append(f"Incident targets asset: {asset['name']} (IP: {asset['properties'].get('ip', 'N/A')})")
                
                # 2. Find vulnerabilities on this asset
                for edge in edges:
                    if edge["src"] == asset["id"] and edge["relationship"] == "exploited_by" and edge["dst_type"] == "Vulnerability":
                        vuln = node_map.get(edge["dst"])
                        if vuln:
                            chain.append(vuln)
                            timeline.append(f"Asset is vulnerable to: {vuln['id']} (Score: {vuln['properties'].get('score', 'N/A')})")
                            
                # 3. Find IOCs linked to this asset or incident
                for edge in edges:
                    if edge["dst"] == asset["id"] and edge["relationship"] == "compromised_by" and edge["src_type"] == "IOC":
                        ioc = node_map.get(edge["src"])
                        if ioc:
                            chain.append(ioc)
                            timeline.append(f"IOC indicator observed: {ioc['name']} ({ioc['properties'].get('threat', '')})")
                            
            return {
                "chain": chain,
                "timeline": timeline
            }
        except Exception as e:
            logger.error(f"Error getting attack chain: {e}")
            return {"chain": [], "timeline": []}
