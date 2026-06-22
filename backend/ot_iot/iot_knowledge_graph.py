"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — IoT Knowledge Graph

Models network architecture and device relationships as a knowledge graph.
Enables BFS blast radius checks, Dijkstra attack path resolution, and lateral movement risk calculations.
"""

import logging
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict, deque

logger = logging.getLogger("niravan.ot_iot.knowledge_graph")
logger.setLevel(logging.INFO)


class IoTKnowledgeGraph:
    """
    Graph representation of IoT/OT network nodes, links, and vulnerability vectors.
    """

    CRITICALITY_MAP: Dict[str, int] = {
        "PLC": 10,
        "SCADA_Server": 10,
        "RTU": 9,
        "Industrial_Gateway": 8,
        "Engineering_Workstation": 8,
        "HVAC_Controller": 7,
        "Smart_Meter": 6,
        "CCTV_Camera": 4,
        "IP_Phone": 3,
        "Printer": 2,
        "unknown": 5
    }

    def __init__(self) -> None:
        # Node storage: node_id -> device properties dictionary
        self._nodes: Dict[str, Dict[str, Any]] = {}
        # Edge storage: src_id -> dst_id -> relationship dictionary
        self._edges: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)

    def add_device(self, device_info: Dict[str, Any]) -> str:
        """
        Adds or updates a device node in the knowledge graph.

        Args:
            device_info: Device attributes (device_id, ip, type, vendor, criticality).

        Returns:
            The generated or matched device ID.
        """
        device_id = device_info.get("device_id") or device_info.get("ip")
        if not device_id:
            raise ValueError("Device info must contain at least 'device_id' or 'ip'")

        # Determine criticality
        device_type = device_info.get("type", "unknown")
        default_crit = self.CRITICALITY_MAP.get(device_type, self.CRITICALITY_MAP["unknown"])
        criticality = device_info.get("criticality") or default_crit

        # Merge new attributes with existing
        existing_info = self._nodes.get(device_id, {})
        merged_info = {**existing_info, **device_info}
        merged_info["criticality"] = criticality
        merged_info["device_id"] = device_id

        self._nodes[device_id] = merged_info
        return device_id

    def add_relationship(self, src: str, dst: str, rel_type: str, props: Dict[str, Any]) -> str:
        """
        Adds a directed connection link between two device nodes.

        Args:
            src: Source node ID.
            dst: Destination node ID.
            rel_type: Connection relationship description (e.g., 'communicates', 'manages', 'controls').
            props: Edge metadata (e.g., port, protocol, weight/exploitability).

        Returns:
            Edge identifier string.
        """
        # Ensure source and destination exist in the nodes store
        if src not in self._nodes:
            self.add_device({"device_id": src, "type": "unknown"})
        if dst not in self._nodes:
            self.add_device({"device_id": dst, "type": "unknown"})

        # Weight represents compromise difficulty (lower weight = easier pivot/compromise)
        weight = props.get("weight")
        if weight is None:
            # Default weight calculation: base on protocol or port security
            port = props.get("port")
            if port in [23, 80, 502]: # unencrypted protocols
                weight = 0.4
            else:
                weight = 1.0

        edge_data = {
            "rel_type": rel_type,
            "weight": weight,
            "properties": props
        }

        self._edges[src][dst] = edge_data
        return f"{src}->{dst}"

    def build_from_discovery(self, discovery_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Populates graph elements using outputs from the Discovery layer.

        Args:
            discovery_result: Contains:
                              'devices': List[Dict]
                              'connections': List[Dict]
        """
        devices = discovery_result.get("devices", [])
        connections = discovery_result.get("connections", [])

        dev_added = 0
        rel_added = 0

        for dev in devices:
            self.add_device(dev)
            dev_added += 1

        for conn in connections:
            src = conn.get("src") or conn.get("src_ip")
            dst = conn.get("dst") or conn.get("dst_ip")
            rel_type = conn.get("rel_type") or "communicates"
            
            if src and dst:
                props = {
                    "port": conn.get("port"),
                    "protocol": conn.get("protocol"),
                    "weight": conn.get("weight")
                }
                self.add_relationship(src, dst, rel_type, props)
                rel_added += 1

        return {
            "devices_added": dev_added,
            "relationships_added": rel_added
        }

    def get_blast_radius(self, device_id: str, max_hops: int = 3) -> Dict[str, Any]:
        """
        Uses BFS to traverse outwards from the specified device and identify reachable assets.
        Computes an impact score reflecting overall risk to high-criticality assets.
        """
        if device_id not in self._nodes:
            return {
                "start_device": device_id,
                "reachable_count": 0,
                "reachable_devices": [],
                "critical_assets_exposed": [],
                "impact_score": 0.0,
                "explanation": "Device not found in the graph."
            }

        # BFS Traversal
        visited = {device_id}
        queue = deque([(device_id, 0)]) # (node, depth)
        reachable_devices = []
        critical_assets = []
        impact_score = 0.0

        # Include start node's criticality as initial context, but don't add to reachable_devices
        start_crit = self._nodes[device_id].get("criticality", 5)

        while queue:
            curr_node, depth = queue.popleft()

            if depth >= max_hops:
                continue

            # Iterate outgoing links
            for neighbor in self._edges.get(curr_node, {}):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))
                    
                    neighbor_props = self._nodes[neighbor]
                    criticality = neighbor_props.get("criticality", 5)
                    
                    # Impact contribution: decreases with distance (decay factor)
                    decay = 1.0 / (depth + 1)
                    node_impact = criticality * decay * 10.0
                    impact_score += node_impact

                    dev_entry = {
                        "device_id": neighbor,
                        "hops": depth + 1,
                        "type": neighbor_props.get("type", "unknown"),
                        "criticality": criticality
                    }
                    reachable_devices.append(dev_entry)

                    # Criticality threshold (>= 8)
                    if criticality >= 8:
                        critical_assets.append(neighbor)

        # Cap impact score at 100.0
        impact_score = min(100.0, impact_score)

        return {
            "start_device": device_id,
            "reachable_count": len(reachable_devices),
            "reachable_devices": reachable_devices,
            "critical_assets_exposed": critical_assets,
            "impact_score": round(impact_score, 2),
            "explanation": (
                f"From {device_id}, an attacker can reach {len(reachable_devices)} device(s) within {max_hops} hops. "
                f"Exposes {len(critical_assets)} critical asset(s). Cumulative impact score: {round(impact_score, 2)}/100."
            )
        }

    def get_attack_path(self, src_id: str, dst_id: str) -> Dict[str, Any]:
        """
        Calculates the shortest logical attack path using Dijkstra's algorithm.
        Edge weights represent the compromise difficulty (lower weight = easier step).
        """
        if src_id not in self._nodes or dst_id not in self._nodes:
            return {
                "path": [],
                "total_weight": float('inf'),
                "path_found": False,
                "details": "Source or destination node not found in graph."
            }

        # Dijkstra algorithm
        distances = {node: float('inf') for node in self._nodes}
        distances[src_id] = 0.0
        previous = {node: None for node in self._nodes}
        unvisited = set(self._nodes.keys())

        while unvisited:
            # Get node with minimum distance
            current = min(unvisited, key=lambda node: distances[node])
            if distances[current] == float('inf'):
                break
            if current == dst_id:
                break

            unvisited.remove(current)

            for neighbor, edge_info in self._edges.get(current, {}).items():
                if neighbor not in unvisited:
                    continue
                
                weight = edge_info.get("weight", 1.0)
                alt = distances[current] + weight
                if alt < distances[neighbor]:
                    distances[neighbor] = alt
                    previous[neighbor] = current

        # Reconstruct path
        path = []
        curr = dst_id
        if previous[curr] is not None or curr == src_id:
            while curr is not None:
                path.insert(0, curr)
                curr = previous[curr]

        path_found = len(path) > 0 and path[0] == src_id

        # Compile details of the hop transitions
        details = []
        if path_found:
            for i in range(len(path) - 1):
                u = path[i]
                v = path[i+1]
                edge_info = self._edges[u][v]
                details.append({
                    "from_node": u,
                    "from_type": self._nodes[u].get("type", "unknown"),
                    "to_node": v,
                    "to_type": self._nodes[v].get("type", "unknown"),
                    "rel_type": edge_info.get("rel_type"),
                    "port": edge_info["properties"].get("port"),
                    "protocol": edge_info["properties"].get("protocol"),
                    "weight_difficulty": edge_info.get("weight")
                })

        return {
            "path": path,
            "total_weight": round(distances[dst_id], 4) if path_found else float('inf'),
            "path_found": path_found,
            "details": details if path_found else "No viable path found."
        }

    def get_lateral_movement_risk(self, device_id: str) -> Dict[str, Any]:
        """
        Assesses the danger posed by the device if compromised, measuring out-degree
        and proximity to critical PLCs/SCADA elements.
        """
        if device_id not in self._nodes:
            return {
                "device_id": device_id,
                "risk_score": 0.0,
                "risk_level": "INFO",
                "details": "Device not found."
            }

        neighbors = self._edges.get(device_id, {})
        out_degree = len(neighbors)

        critical_targets_exposed = []
        vulnerable_adjacent_targets = []
        
        # Risk factors
        exposure_points = 0.0

        for neighbor, edge_info in neighbors.items():
            neighbor_props = self._nodes[neighbor]
            criticality = neighbor_props.get("criticality", 5)
            weight = edge_info.get("weight", 1.0)

            # High criticality target
            if criticality >= 8:
                critical_targets_exposed.append(neighbor)
                exposure_points += criticality * 2.5

            # Vulnerable link (weight < 0.5)
            if weight < 0.5:
                vulnerable_adjacent_targets.append(neighbor)
                exposure_points += 15.0

        # Scale out-degree risk
        exposure_points += min(30.0, out_degree * 5.0)
        risk_score = min(100.0, exposure_points)

        # Risk Classification
        if risk_score >= 75.0:
            risk_level = "CRITICAL"
        elif risk_score >= 50.0:
            risk_level = "HIGH"
        elif risk_score >= 25.0:
            risk_level = "MEDIUM"
        elif risk_score > 0.0:
            risk_level = "LOW"
        else:
            risk_level = "INFO"

        return {
            "device_id": device_id,
            "out_degree": out_degree,
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "vulnerable_adjacent_targets": vulnerable_adjacent_targets,
            "critical_targets_exposed": critical_targets_exposed,
            "details": (
                f"Lateral movement risk is {risk_level} (score: {round(risk_score, 2)}). "
                f"Connected directly to {out_degree} nodes, exposing {len(critical_targets_exposed)} critical assets."
            )
        }
