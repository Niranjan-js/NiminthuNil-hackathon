import math
from typing import List, Dict, Any, Tuple

class VectorMemory:
    def __init__(self):
        # List of (id, text, vector, metadata)
        self.records: List[Tuple[str, str, List[float], Dict[str, Any]]] = []

    @staticmethod
    def get_simple_hash_embedding(text: str) -> List[float]:
        # Helper to generate a deterministic mock embedding vector of size 8
        words = text.lower().split()
        vector = [0.0] * 8
        for i, word in enumerate(words):
            val = sum(ord(c) for c in word) % 100 / 100.0
            vector[i % 8] += val
        
        # Normalize
        norm = math.sqrt(sum(v*v for v in vector))
        if norm > 0:
            vector = [v / norm for v in vector]
        return vector

    def add_record(self, record_id: str, text: str, metadata: Dict[str, Any] = None):
        vec = self.get_simple_hash_embedding(text)
        self.records.append((record_id, text, vec, metadata or {}))

    def search_similar(self, query_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        q_vec = self.get_simple_hash_embedding(query_text)
        results = []
        for rec_id, text, vec, meta in self.records:
            # Cosine similarity
            dot_product = sum(a*b for a, b in zip(q_vec, vec))
            results.append({
                "id": rec_id,
                "text": text,
                "score": round(dot_product, 4),
                "metadata": meta
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]
