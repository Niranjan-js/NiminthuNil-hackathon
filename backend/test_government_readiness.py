import os
import datetime
import pytest
from fastapi.testclient import TestClient
from main import app, Base, engine, SessionLocal, seed_database, seed_cases, LoginLogModel
from ai_gateway import AIGateway

@pytest.fixture(scope="module")
def client_auth():
    # Setup test database tables
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
        seed_cases(db)
    finally:
        db.close()
        
    with TestClient(app) as client:
        # Avoid rate limits by using pre-seeded admin login
        login_res = client.post("/api/v1/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        yield client, headers

def test_impossible_travel_detection(client_auth):
    client, headers = client_auth
    
    # 1. Send first successful login telemetry log
    log1 = {
        "source_type": "windows_log",
        "host": "PROD-WEB-01",
        "log_data": {
            "EventID": 4624,
            "TargetUserName": "traveler@niravan.ai",
            "IpAddress": "185.123.4.5",
            "Computer": "PROD-WEB-01"
        }
    }
    res1 = client.post("/api/v1/ingest/telemetry", json=log1)
    assert res1.status_code == 200
    
    # 2. Send second successful login telemetry log from different IP within 5 minutes
    log2 = {
        "source_type": "windows_log",
        "host": "PROD-WEB-01",
        "log_data": {
            "EventID": 4624,
            "TargetUserName": "traveler@niravan.ai",
            "IpAddress": "198.51.100.42",
            "Computer": "PROD-WEB-01"
        }
    }
    res2 = client.post("/api/v1/ingest/telemetry", json=log2)
    assert res2.status_code == 200
    res_data = res2.json()
    assert res_data["status"] == "triggered"
    assert "Impossible Travel" in res_data["rule"]
    assert res_data["confidence"] >= 90.0

def test_password_spray_detection(client_auth):
    client, headers = client_auth
    
    # Send failed login logs from the same IP to 3 different users in a short window
    ip = "192.168.99.99"
    users = ["spray_u1@niravan.ai", "spray_u2@niravan.ai", "spray_u3@niravan.ai"]
    
    # Send first two failures
    for u in users[:-1]:
        log = {
            "source_type": "windows_log",
            "host": "PROD-WEB-01",
            "log_data": {
                "EventID": 4625,
                "TargetUserName": u,
                "IpAddress": ip,
                "Computer": "PROD-WEB-01"
            }
        }
        res = client.post("/api/v1/ingest/telemetry", json=log)
        assert res.status_code == 200
        
    # The third failure triggers the password spray rule
    log = {
        "source_type": "windows_log",
        "host": "PROD-WEB-01",
        "log_data": {
            "EventID": 4625,
            "TargetUserName": users[-1],
            "IpAddress": ip,
            "Computer": "PROD-WEB-01"
        }
    }
    res = client.post("/api/v1/ingest/telemetry", json=log)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["status"] == "triggered"
    assert "Password Spray" in res_data["rule"]
    assert res_data["confidence"] >= 90.0

def test_privilege_escalation_detection(client_auth):
    client, headers = client_auth
    
    log = {
        "source_type": "sysmon",
        "host": "PROD-WEB-01",
        "log_data": {
            "EventID": 1,
            "CommandLine": "sudo su - root",
            "Computer": "PROD-WEB-01",
            "User": "normaluser"
        }
    }
    res = client.post("/api/v1/ingest/telemetry", json=log)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["status"] == "triggered"
    assert "Privilege Escalation" in res_data["rule"]

def test_deception_honeypot_user(client_auth):
    client, headers = client_auth
    
    log = {
        "source_type": "windows_log",
        "host": "PROD-WEB-01",
        "log_data": {
            "EventID": 4624,
            "TargetUserName": "honey_admin",
            "IpAddress": "192.168.1.100",
            "Computer": "PROD-WEB-01"
        }
    }
    res = client.post("/api/v1/ingest/telemetry", json=log)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["status"] == "triggered"
    assert "Deception Lure Triggered" in res_data["rule"]
    assert res_data["confidence"] == 100.0

def test_deception_honeytoken_share(client_auth):
    client, headers = client_auth
    
    log = {
        "source_type": "sysmon",
        "host": "PROD-WEB-01",
        "log_data": {
            "EventID": 1,
            "CommandLine": "net use X: \\\\HONEY-SHARE\\backup",
            "Computer": "PROD-WEB-01",
            "User": "attacker"
        }
    }
    res = client.post("/api/v1/ingest/telemetry", json=log)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["status"] == "triggered"
    assert "Deception Lure Triggered" in res_data["rule"]
    assert res_data["confidence"] == 100.0

def test_compliance_stats_endpoint(client_auth):
    client, headers = client_auth
    
    res = client.get("/api/v1/compliance/stats", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "composite_score" in data
    assert "cert_in" in data
    assert "iso_27001" in data
    assert "nist_csf" in data
    assert "dpdp_act" in data
    assert "checklist" in data

def test_reputation_scores_endpoint(client_auth):
    client, headers = client_auth
    
    res = client.get("/api/v1/reputation/scores", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "assets" in data
    assert "users" in data
    assert len(data["assets"]) > 0
    assert len(data["users"]) > 0

def test_ai_gateway_provider(monkeypatch):
    # Test default fallback
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert AIGateway.get_model_provider() == "offline_fallback"
    
    # Test OpenAI env
    monkeypatch.setenv("OPENAI_API_KEY", "mock-key")
    assert AIGateway.get_model_provider() == "openai"
    
    # Test Gemini env
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "mock-key")
    assert AIGateway.get_model_provider() == "gemini"

def test_knowledge_graph_endpoints(client_auth):
    client, headers = client_auth
    
    # 1. Create a node
    node_res = client.post("/api/v1/knowledge-graph/node", headers=headers, json={
        "entity_type": "Campaign",
        "entity_id": "camp-lockbit",
        "name": "LockBit Ransomware Campaign",
        "risk_weight": 95,
        "properties": {"actor": "FIN7", "target_sector": "Healthcare"}
    })
    assert node_res.status_code == 200
    assert node_res.json()["status"] == "success"
    
    # 2. Create another node representing an Asset
    asset_res = client.post("/api/v1/knowledge-graph/node", headers=headers, json={
        "entity_type": "Asset",
        "entity_id": "ast-hosp-db",
        "name": "Hospital Core Database",
        "risk_weight": 80
    })
    assert asset_res.status_code == 200
    
    # 3. Create a relationship between Campaign and Asset
    edge_res = client.post("/api/v1/knowledge-graph/relationship", headers=headers, json={
        "source_type": "Campaign",
        "source_id": "camp-lockbit",
        "target_type": "Asset",
        "target_id": "ast-hosp-db",
        "relationship": "targets",
        "weight": 2.5,
        "properties": {"vector": "Phishing"}
    })
    assert edge_res.status_code == 200
    assert edge_res.json()["status"] == "success"
    
    # 4. Search the knowledge graph
    search_res = client.get("/api/v1/knowledge-graph?query=LockBit", headers=headers)
    assert search_res.status_code == 200
    data = search_res.json()
    assert len(data["nodes"]) > 0
    assert data["nodes"][0]["entity_id"] == "camp-lockbit"
    assert len(data["edges"]) > 0
    assert data["edges"][0]["relationship"] == "targets"

def test_security_economics_endpoint(client_auth):
    client, headers = client_auth
    
    res = client.get("/api/v1/economics/stats", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_risk_exposure" in data
    assert "total_patch_cost" in data
    assert "total_breach_impact" in data
    assert len(data["assets"]) > 0
    assert "potential_impact" in data["assets"][0]
    assert "patch_cost" in data["assets"][0]
    assert "risk_exposure" in data["assets"][0]
