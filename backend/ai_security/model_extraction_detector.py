import time
from typing import Dict, Tuple

class ModelExtractionDetector:
    def __init__(self, request_threshold: int = 20, time_window: float = 60.0):
        self.threshold = request_threshold
        self.window = time_window
        # Stores user_id/ip -> list of timestamps
        self.history: Dict[str, list] = {}

    def log_request_and_check(self, client_id: str) -> bool:
        """Returns True if the client exceeds the model extraction rate threshold (potential attack)."""
        now = time.time()
        if client_id not in self.history:
            self.history[client_id] = []
        
        # Filter older timestamps
        self.history[client_id] = [t for t in self.history[client_id] if now - t < self.window]
        self.history[client_id].append(now)

        return len(self.history[client_id]) > self.threshold
