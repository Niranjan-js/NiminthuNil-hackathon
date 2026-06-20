from typing import Dict, Any, List

class BGPRouteLeakDetector:
    @staticmethod
    def inspect_routing_table(route_announcement: Dict[str, Any]) -> Dict[str, Any]:
        """Detects if AS path contains unexpected intermediate transit networks (classic route leak)."""
        path = route_announcement.get("as_path", [])
        leak = False
        reason = "Normal path"
        
        # If government transit AS 9988 passes through a customer/non-transit AS unexpectedly
        if len(path) > 3:
            for i in range(1, len(path) - 1):
                if path[i] in [8888, 7777]:  # Customer ASes acting as transit
                    leak = True
                    reason = f"Route Leak Detected: Customer AS {path[i]} is acting as transit provider between AS {path[i-1]} and AS {path[i+1]}!"
                    break

        return {
            "route": route_announcement.get("prefix"),
            "leak_detected": leak,
            "description": reason
        }
