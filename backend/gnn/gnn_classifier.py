from typing import List, Dict, Any

class GNNNodeClassifier:
    @staticmethod
    def classify_nodes_with_gnn(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, str]:
        """Runs a message-passing classification simulation to detect hidden lateral risk nodes."""
        predictions = {}
        # Simple label propagation simulation
        compromised = set()
        for node in nodes:
            if node.get("properties", {}).get("risk_score", 0.0) >= 80:
                compromised.add(node["id"])
        
        # Propagate risk across links
        for edge in edges:
            if edge["source"] in compromised:
                predictions[edge["target"]] = "High Risk (Propagated)"
            elif edge["target"] in compromised:
                predictions[edge["source"]] = "High Risk (Propagated)"

        return predictions
