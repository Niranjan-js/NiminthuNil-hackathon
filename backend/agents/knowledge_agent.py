import logging
from typing import Dict, Any, List
from backend.knowledge_graph.graph_search import GraphSearcher

logger = logging.getLogger("niravan.agents.knowledge_agent")
searcher = GraphSearcher()

class KnowledgeAgent:
    """
    Knowledge Agent traverses the Knowledge Graph to link asset profiles and CVEs to incidents.
    """
    def enrich_incident_relations(self, asset_id: str) -> Dict[str, Any]:
        related_incidents = searcher.find_all_incidents_for_asset(asset_id)
        return {
            "status": "success",
            "asset_id": asset_id,
            "incident_count": len(related_incidents),
            "linked_incident_ids": related_incidents
        }
