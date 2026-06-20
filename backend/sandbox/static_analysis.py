import math
from typing import Dict, Any

class StaticMalwareAnalyzer:
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def analyze_buffer(cls, file_name: str, file_data: bytes) -> Dict[str, Any]:
        entropy = cls.calculate_entropy(file_data)
        suspicious = entropy > 7.2  # High entropy suggests packing/encryption
        
        # Check simple signatures in raw content
        signatures_matched = []
        if b"GetProcAddress" in file_data or b"LoadLibrary" in file_data:
            signatures_matched.append("Dynamic API Resolution")
        if b"HttpSendRequest" in file_data:
            signatures_matched.append("Network Connections Capability")

        return {
            "file_name": file_name,
            "file_size": len(file_data),
            "entropy": entropy,
            "suspicious_entropy": suspicious,
            "detected_signatures": signatures_matched
        }
