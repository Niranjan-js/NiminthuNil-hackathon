import logging
from typing import Dict, Any, List, Optional, Set, Tuple

logger = logging.getLogger("niravan.ot_iot.topology_mapper")


class IoTTopologyMapper:
    """
    Network Topology Mapping Engine for NIRAVAN OT/IoT Defense Layer.
    Builds structured layouts representing device connectivity through Switched, Routers,
    and Firewalls. Detects network loops, finds shortest paths, and aggregates subnet members.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[Dict[str, str]] = []

    def build_topology(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Builds network topology layout (Device -> Switch -> Router -> Firewall).
        Clears previous state and maps the new device set.
        """
        self._nodes.clear()
        self._edges.clear()

        # Define router and firewall nodes
        router_id = "Router_Core"
        firewall_id = "Firewall_Edge"

        self._nodes[router_id] = {
            "id": router_id,
            "type": "Router",
            "label": "Core Router",
            "ip": "10.0.0.1"
        }
        self._nodes[firewall_id] = {
            "id": firewall_id,
            "type": "Firewall",
            "label": "Edge Firewall",
            "ip": "10.0.0.2"
        }

        # Add Core Router -> Edge Firewall edge
        self._edges.append({"source": router_id, "target": firewall_id})

        subnets_detected: Set[str] = set()

        for dev in devices:
            dev_id = dev.get("id") or dev.get("ip") or dev.get("mac")
            if not dev_id:
                # Generate unique ID if not present
                dev_id = f"Dev_{hash(dev.get('model', '')) & 0xffff}"

            ip = dev.get("ip", "Unknown")
            subnet = self._get_subnet_from_ip(ip)

            # Store device node
            self._nodes[dev_id] = {
                "id": dev_id,
                "type": "Device",
                "label": dev.get("model") or dev.get("vendor") or "Generic Device",
                "ip": ip,
                "vendor": dev.get("vendor", "Unknown"),
                "device_type": dev.get("device_type", "Unknown")
            }

            # Switch identification per subnet
            switch_id = f"Switch_{subnet.replace('/', '_')}"
            if subnet not in subnets_detected:
                subnets_detected.add(subnet)
                self._nodes[switch_id] = {
                    "id": switch_id,
                    "type": "Switch",
                    "label": f"Switch ({subnet})",
                    "subnet": subnet
                }
                # Connect Switch to Core Router
                self._edges.append({"source": switch_id, "target": router_id})

            # Connect Device to Switch
            self._edges.append({"source": dev_id, "target": switch_id})

        # Simulate a redundant loop for testing if we have at least two subnets
        if len(subnets_detected) >= 2:
            sorted_subnets = sorted(list(subnets_detected))
            sw1 = f"Switch_{sorted_subnets[0].replace('/', '_')}"
            sw2 = f"Switch_{sorted_subnets[1].replace('/', '_')}"
            # Bridge link creating a loop: sw1 -> Router_Core -> sw2 -> sw1
            self._edges.append({"source": sw1, "target": sw2})
            logger.warning(f"Simulating redundant loop/bridge link between {sw1} and {sw2}")

        logger.info(f"Built topology with {len(self._nodes)} nodes and {len(self._edges)} edges.")
        return {
            "nodes": self._nodes,
            "edges": self._edges
        }

    def get_neighbors(self, device_id: str) -> List[str]:
        """Returns direct neighbors of a specified device/node."""
        neighbors = set()
        for edge in self._edges:
            if edge["source"] == device_id:
                neighbors.add(edge["target"])
            elif edge["target"] == device_id:
                neighbors.add(edge["source"])
        return sorted(list(neighbors))

    def find_shortest_path(self, src_id: str, dst_id: str) -> List[str]:
        """Finds the shortest path between two nodes using Breadth-First Search (BFS)."""
        if src_id not in self._nodes or dst_id not in self._nodes:
            return []
        if src_id == dst_id:
            return [src_id]

        # Build adjacency graph
        adj: Dict[str, List[str]] = {node: [] for node in self._nodes}
        for edge in self._edges:
            s, t = edge["source"], edge["target"]
            if s in adj and t in adj:
                adj[s].append(t)
                adj[t].append(s)

        queue = [[src_id]]
        visited = {src_id}

        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node == dst_id:
                return path
            for neighbor in adj[node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return []

    def get_subnets(self) -> Dict[str, List[str]]:
        """Maps subnet names to the list of device IDs belonging to each subnet."""
        subnets: Dict[str, List[str]] = {}
        for node_id, node_meta in self._nodes.items():
            if node_meta.get("type") == "Device":
                ip = node_meta.get("ip", "Unknown")
                subnet = self._get_subnet_from_ip(ip)
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append(node_id)
        return subnets

    def detect_loops(self) -> List[List[str]]:
        """Detects loops (cycles) in the topology graph and returns them normalized."""
        visited: Set[str] = set()
        loops: List[List[str]] = []

        # Build adjacency list
        adj: Dict[str, List[str]] = {node: [] for node in self._nodes}
        for edge in self._edges:
            s, t = edge["source"], edge["target"]
            if s in adj and t in adj:
                adj[s].append(t)
                adj[t].append(s)

        def dfs(node: str, parent: Optional[str], path: List[str]) -> None:
            visited.add(node)
            for neighbor in adj[node]:
                if neighbor == parent:
                    continue
                if neighbor in visited:
                    if neighbor in path:
                        idx = path.index(neighbor)
                        cycle = path[idx:] + [neighbor]
                        normalized = self._normalize_cycle(cycle)
                        if normalized not in loops:
                            loops.append(normalized)
                else:
                    dfs(neighbor, node, path + [neighbor])

        for node in self._nodes:
            if node not in visited:
                dfs(node, None, [node])

        return loops

    @staticmethod
    def _normalize_cycle(cycle: List[str]) -> List[str]:
        """Normalizes an undirected cycle path to prevent duplicate cycle reports."""
        nodes = cycle[:-1]
        # Rotate starting with lexically smallest node
        min_idx = nodes.index(min(nodes))
        rotated = nodes[min_idx:] + nodes[:min_idx]

        # Consider reverse rotation to keep undirected loops identical
        rotated_rev = list(reversed(rotated))
        min_idx_rev = rotated_rev.index(min(rotated_rev))
        rotated_rev = rotated_rev[min_idx_rev:] + rotated_rev[:min_idx_rev]

        best = min(rotated, rotated_rev)
        return best + [best[0]]

    @staticmethod
    def _get_subnet_from_ip(ip: str) -> str:
        """Parses subnet from IP address."""
        if not ip or ip == "Unknown" or ":" in ip:
            # Fallback for non-IPv4 or IPv6
            return "192.168.1.0/24"
        parts = ip.split(".")
        if len(parts) >= 3:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "192.168.1.0/24"
