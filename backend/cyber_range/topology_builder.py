from typing import List, Dict, Any

class CyberRangeTopologyBuilder:
    @staticmethod
    def build_district_topology() -> Dict[str, Any]:
        """Builds a simulated network topology for a local district cyber twin."""
        subnets = {
            "Collectorate_Subnet": ["10.100.1.10 (Collector Portal)", "10.100.1.20 (Database)"],
            "Hospital_Subnet": ["10.100.2.10 (EMR Server)", "10.100.2.20 (Vitals IoT gateway)"],
            "School_Subnet": ["10.100.3.10 (EMIS Web Server)", "10.100.3.20 (Student DB)"],
            "Police_Subnet": ["10.100.4.10 (FIR Logs)", "10.100.4.20 (CCTV Storage)"],
            "Treasury_Subnet": ["10.100.5.10 (Pension Ledger)", "10.100.5.20 (Auditing)"]
        }

        # Subnet routes
        routes = [
            {"source": "Collectorate_Subnet", "target": "Treasury_Subnet", "allowed": True},
            {"source": "Hospital_Subnet", "target": "Collectorate_Subnet", "allowed": False},
            {"source": "School_Subnet", "target": "Collectorate_Subnet", "allowed": False}
        ]

        return {
            "name": "Tamil Nadu District Twin Cyber Range Topology",
            "segments": subnets,
            "routing_rules": routes
        }
