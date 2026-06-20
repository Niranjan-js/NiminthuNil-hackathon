from typing import List, Dict, Any
from .neo4j_client import neo4j_client

class IOCGraphBuilder:
    @staticmethod
    def map_ioc_network(ioc_value: str, threat_actor: str, malware_family: str) -> Dict[str, Any]:
        """Maps an IOC to its associated Threat Actor and Malware families, updating the neo4j client."""
        neo4j_client.add_node("IOC", ioc_value, f"Indicator:{ioc_value}", {"value": ioc_value})
        neo4j_client.add_node("ThreatActor", threat_actor, threat_actor)
        neo4j_client.add_node("Malware", malware_family, malware_family)

        neo4j_client.add_relationship(f"ThreatActor:{threat_actor}", f"Malware:{malware_family}", "USES")
        neo4j_client.add_relationship(f"Malware:{malware_family}", f"IOC:{ioc_value}", "INDICATES")

        return {
            "ioc": ioc_value,
            "actor": threat_actor,
            "malware": malware_family
        }
