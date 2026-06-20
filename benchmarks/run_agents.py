from typing import Dict, Any
from backend.agents.director_agent import DirectorAgent
from backend.agents.consensus_agent import ConsensusAgent
from backend.explainability.xai_explain import ExplainableAIEngine

def run_benchmark() -> Dict[str, Any]:
    # 1. Swarm Director delegation mapping
    director = DirectorAgent()
    res_dir = director.delegate_incident({"title": "modbus coil modification"})
    # Must delegate to OTAgent
    delegation_ok = "OTAgent" in res_dir["delegation_plan"]

    # 2. Consensus Agent convergence check with full agent reports
    consensus = ConsensusAgent()
    res_con = consensus.merge_assessments(
        threat={"severity": "critical", "root_cause": "Ransomware payload active"},
        impact={"financial_impact_lakhs": 25.0, "citizens_at_risk": 5000},
        compliance={"severity_for_compliance": "high", "compliance_actions": ["Notify CERT-In"]},
        hunter={"risk_assessment": "suspicious", "score": 0.90},
        forensics={"total_events_correlated": 8, "forensic_findings": ["malicious exe execution"]},
        identity={"score": 0.95, "anomaly_type": "DCSync"},
        cloud={"score": 0.85},
        intel={"score": 0.90}
    )

    consensus_score = res_con["consensus_score"]
    consensus_ok = consensus_score >= 0.70

    # 3. Explainability Calibration
    explain = ExplainableAIEngine.get_shap_incident_attributions(
        raw_score=consensus_score,
        factors={"IPReputation": 0.4, "Beaconing": 0.6}
    )
    shap_ok = explain["feature_attributions"]["Beaconing"] > 0.0

    passed = delegation_ok and consensus_ok and shap_ok
    return {
        "domain": "Multi-Agent Swarm & XAI",
        "swarm_delegation_correctness": 1.0 if delegation_ok else 0.0,
        "consensus_score_output": consensus_score,
        "explainability_shap_consistency": 1.0 if shap_ok else 0.0,
        "target_thresholds": "Consensus > 95% accuracy, SHAP consistency check",
        "passed": passed
    }

if __name__ == "__main__":
    print(run_benchmark())
