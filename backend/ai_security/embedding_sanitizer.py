from typing import List

class EmbeddingSanitizer:
    @staticmethod
    def sanitize_vector(vector: List[float]) -> List[float]:
        # Clip embeddings to standard normalization bounds to prevent vector poisoning/overflow
        return [max(-1.0, min(1.0, val)) for val in vector]

    @staticmethod
    def sanitize_query_text(text: str) -> str:
        # Strip out non-ascii control chars that could disrupt tokenizers
        return "".join(ch for ch in text if ch.isprintable() or ch in "\n\r\t")
