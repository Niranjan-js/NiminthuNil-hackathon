from typing import Any, Dict
from .neo4j_client import neo4j_client

class EntityMapper:
    @staticmethod
    def map_sql_to_graph(model_name: str, instance: Any) -> Dict[str, Any]:
        """Translates SQL/ORM instances to Graph entities."""
        properties = {}
        node_id = ""
        name = ""

        if model_name == "AssetModel":
            node_id = getattr(instance, "id", str(getattr(instance, "ip_address", "")))
            name = getattr(instance, "hostname", "Asset")
            properties = {
                "ip": getattr(instance, "ip_address", ""),
                "os": getattr(instance, "operating_system", ""),
                "criticality": getattr(instance, "criticality", "medium"),
                "risk_score": getattr(instance, "risk_score", 50.0)
            }
            neo4j_client.add_node("Asset", node_id, name, properties)

        elif model_name == "IncidentModel":
            node_id = str(getattr(instance, "id", ""))
            name = getattr(instance, "title", "Incident")
            properties = {
                "severity": getattr(instance, "severity", "medium"),
                "status": getattr(instance, "status", "open"),
                "mitre_ttps": getattr(instance, "mitre_ttps", "")
            }
            neo4j_client.add_node("Incident", node_id, name, properties)

        return {"node_id": node_id, "name": name, "properties": properties}
