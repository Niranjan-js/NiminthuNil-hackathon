from typing import List, Dict, Any
from backend.memory.vector_memory import VectorMemory
from .graph_retriever import GraphRAGRetriever

class HybridSearcher:
    def __init__(self, vector_db: VectorMemory):
        self.vector_db = vector_db

    def execute_hybrid_search(self, query: str, edges: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merges vector search hits with graph relational context mappings."""
        # 1. Vector hits
        vec_hits = self.vector_db.search_similar(query, top_k=2)

        # 2. Extract potential entity from query and fetch subgraph context
        graph_hits = []
        for word in query.split():
            clean_word = word.strip(",.!?\"'")
            if len(clean_word) > 3:
                sub_edges = GraphRAGRetriever.retrieve_entity_subgraph(clean_word, edges)
                if sub_edges:
                    graph_hits.extend(sub_edges)

        # Deduplicate graph hits
        seen = set()
        dedup_graph = []
        for edge in graph_hits:
            key = (edge["source"], edge["target"], edge.get("relationship"))
            if key not in seen:
                seen.add(key)
                dedup_graph.append(edge)

        return {
            "query": query,
            "vector_search_results": vec_hits,
            "graph_context_results": dedup_graph
        }
