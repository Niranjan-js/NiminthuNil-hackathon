import math
from typing import List, Dict, Any

class NetflowAnalyzer:
    @staticmethod
    def detect_c2_beaconing(timestamps: List[float], interval_seconds: float = 60.0) -> Dict[str, Any]:
        """Calculates time interval variance in connections to flag C2 periodic beacons."""
        if len(timestamps) < 4:
            return {"beaconing_detected": False, "variance": 0.0, "reason": "Insufficient flow data."}

        intervals = []
        for i in range(len(timestamps) - 1):
            intervals.append(timestamps[i+1] - timestamps[i])

        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Variance close to 0 indicates high periodicity (beaconing)
        beacon = std_dev < 3.0 and abs(mean - interval_seconds) < 5.0
        return {
            "beaconing_detected": beacon,
            "mean_interval_seconds": round(mean, 2),
            "std_dev_seconds": round(std_dev, 2),
            "variance": round(variance, 4)
        }
