import json
import pytest
from fastapi.testclient import TestClient
from main import app, get_db, SessionLocal, Base, engine, seed_database, seed_cases
from correlation_engine import CorrelationEngine
from defense_memory import DefenseMemory
from main import IncidentModel, FeedbackModel, DefenseMemoryModel, EvaluationMetricModel, AssetModel, GraphNodeModel, GraphEdgeModel

# Single shared client session and auth token to avoid rate limits (429)
@pytest.fixture(scope="module")
def client_auth():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
        seed_cases(db)
    finally:
        db.close()
        
    with TestClient(app) as client:
        login_res = client.post("/api/v1/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        yield client, headers

def test_feedback_and_graph_learning(client_auth):
    client, headers = client_auth

    # 1. Get an incident to submit feedback on
    incidents_res = client.get("/api/v1/incidents", headers=headers)
    assert incidents_res.status_code == 200
    incidents = incidents_res.json()
    assert len(incidents) > 0
    inc_id = incidents[0]["id"]

    # 2. Submit false positive feedback
    fb_payload = {
        "feedback_type": "false_positive",
        "comments": "This was a scheduled administrative login, not an attack."
    }
    fb_res = client.post(f"/api/v1/incidents/{inc_id}/feedback", headers=headers, json=fb_payload)
    assert fb_res.status_code == 200
    assert fb_res.json()["status"] == "success"

    # Verify incident is closed/suppressed
    db = SessionLocal()
    try:
        inc = db.query(IncidentModel).filter(IncidentModel.id == inc_id).first()
        assert inc.status == "suppressed"

        # Check Knowledge Graph learning node
        fb_node = db.query(GraphNodeModel).filter(
            GraphNodeModel.entity_type == "Feedback",
            GraphNodeModel.name.like("%false_positive%")
        ).first()
        assert fb_node is not None
        
        # Check edge exists
        fb_edge = db.query(GraphEdgeModel).filter(
            GraphEdgeModel.target_type == "Feedback",
            GraphEdgeModel.relationship == "has_feedback"
        ).first()
        assert fb_edge is not None
        assert fb_edge.weight == -1.0
    finally:
        db.close()

def test_adaptive_confidence_suppression():
    db = SessionLocal()
    try:
        # Seed an asset
        asset = db.query(AssetModel).first()
        host_name = asset.name if asset else "PROD-WEB-01"
        
        # Ingest a telemetry event to trigger a rule
        rule_name = "PowerShell Credential Dump (SIG-004)"
        # Seed false positive feedback history for this rule/host
        for _ in range(3):
            fb = FeedbackModel(
                incident_id="inc-test-fp",
                user_id="test@niravan.ai",
                feedback_type="false_positive",
                comments="FP test",
                rule_triggered=rule_name,
                host=host_name
            )
            db.add(fb)
        db.commit()

        # Run correlation with sysmon logs triggering mimikatz (critical severity)
        log_payload = {
            "EventID": 1,
            "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
            "Computer": host_name,
            "User": "root",
            "ip_address": "185.220.101.47",
            "source_type": "sysmon",
            "raw_payload": {}
        }
        
        # Trigger event correlation
        res = CorrelationEngine.correlate_event(db, "sysmon", log_payload)
        assert res["status"] == "triggered"
        
        # Verify confidence was reduced below 90% due to false positive history
        assert res["confidence"] < 90.0
        
    finally:
        db.close()

def test_defense_memory_success_calculation():
    db = SessionLocal()
    try:
        # Record a successful mitigation
        DefenseMemory.record_action(db, pattern="Brute Force", action="block_ip", result="successful")
        
        # Record a failed mitigation
        DefenseMemory.record_action(db, pattern="Brute Force", action="block_ip", result="failed")
        
        # Compute success rate
        rate = DefenseMemory.get_action_success_rate(db, pattern="Brute Force", action="block_ip")
        assert rate == 0.5
        
        # Check all memories
        mems = DefenseMemory.get_all_memory(db)
        assert len(mems) >= 2
    finally:
        db.close()

def test_self_evaluation_metrics_generation(client_auth):
    client, headers = client_auth

    # Run evaluation
    eval_res = client.post("/api/v1/self-evaluation", headers=headers)
    assert eval_res.status_code == 200
    metrics = eval_res.json()["metrics"]
    assert "precision" in metrics
    assert "recall" in metrics
    assert "accuracy" in metrics
    
    # Check metrics history retrieval
    hist_res = client.get("/api/v1/self-evaluation/metrics", headers=headers)
    assert hist_res.status_code == 200
    assert "latest" in hist_res.json()
    assert "history" in hist_res.json()

def test_defense_memory_api(client_auth):
    client, headers = client_auth

    # Check defense memory endpoint
    mem_res = client.get("/api/v1/defense-memory", headers=headers)
    assert mem_res.status_code == 200
    data = mem_res.json()
    assert "success_rate" in data
    assert "total_actions" in data
