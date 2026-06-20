from typing import List, Dict, Any

class GraphRAGRetriever:
    @staticmethod
    def retrieve_entity_subgraph(entity_value: str, edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Queries relationships linked to a specific entity to feed into LLM prompt contexts."""
        subgraph = []
        for edge in edges:
            if entity_value in edge["source"] or entity_value in edge["target"]:
                subgraph.append(edge)
        return subgraph
