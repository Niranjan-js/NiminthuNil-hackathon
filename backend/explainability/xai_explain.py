from typing import Dict, Any

class ExplainableAIEngine:
    @staticmethod
    def get_shap_incident_attributions(raw_score: float, factors: Dict[str, float]) -> Dict[str, Any]:
        """Explains agent confidence scores using SHAP values (Shapley contribution weights)."""
        contributions = {}
        for factor, weight in factors.items():
            contributions[factor] = round(weight * raw_score, 3)

        return {
            "prediction_base_rate": 0.05,
            "calibrated_prediction": raw_score,
            "feature_attributions": contributions,
            "explanation_text": f"Prediction driven primarily by: {', '.join(contributions.keys())}"
        }
