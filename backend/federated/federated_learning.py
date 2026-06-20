from typing import List, Dict, Any

class FederatedLearningClient:
    @staticmethod
    def aggregate_node_weights(client_weights: List[Dict[str, float]]) -> Dict[str, float]:
        """Performs Federated Averaging (FedAvg) over multiple local SOC models to update global weights."""
        if not client_weights:
            return {}
        global_weights = {}
        keys = client_weights[0].keys()
        for key in keys:
            global_weights[key] = sum(client[key] for client in client_weights) / len(client_weights)
        return global_weights
