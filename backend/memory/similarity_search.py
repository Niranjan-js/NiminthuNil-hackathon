from typing import List, Dict, Any
from .vector_memory import VectorMemory

class IncidentSimilaritySearcher:
    def __init__(self):
        self.vector_db = VectorMemory()

    def index_past_incidents(self, incidents: List[Dict[str, Any]]):
        for inc in incidents:
            text = f"{inc.get('title', '')} {inc.get('description', '')}"
            self.vector_db.add_record(str(inc.get("id")), text, inc)

    def find_nearest_incidents(self, title: str, description: str) -> List[Dict[str, Any]]:
        query = f"{title} {description}"
        return self.vector_db.search_similar(query, top_k=3)
