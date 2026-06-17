import pytest
from fastapi.testclient import TestClient
from main import app, Base, engine, SessionLocal, seed_database, seed_cases, IncidentModel, CaseModel, ServiceAvailabilityModel

@pytest.fixture(scope="module")
def client_auth():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.query(ServiceAvailabilityModel).delete()
        db.commit()
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

def test_citizen_impact_schema_attributes(client_auth):
    client, headers = client_auth
    
    res = client.get("/api/v1/incidents", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) > 0
    first_inc = data[0]
    assert "affected_citizens" in first_inc
    assert "affected_services" in first_inc
    assert "affected_departments" in first_inc
    assert "estimated_recovery_time" in first_inc
    
    ransom_inc = next(i for i in data if i["id"] == "inc-9481")
    assert ransom_inc["affected_citizens"] == 240000
    assert "EMIS School Registry" in ransom_inc["affected_services"]
    assert "School Education Department" in ransom_inc["affected_departments"]
    assert ransom_inc["estimated_recovery_time"] == "12 hours"

    res_cases = client.get("/api/v1/cases", headers=headers)
    assert res_cases.status_code == 200
    cases_data = res_cases.json()
    assert len(cases_data) > 0
    first_case = cases_data[0]
    assert "affected_citizens" in first_case
    assert "affected_services" in first_case
    assert "affected_departments" in first_case
    assert "estimated_recovery_time" in first_case
    
    ransom_case = next(c for c in cases_data if c["id"] == "case-9481")
    assert ransom_case["affected_citizens"] == 240000
    assert "EMIS School Registry" in ransom_case["affected_services"]

def test_service_availability_endpoint(client_auth):
    client, headers = client_auth
    res = client.get("/api/v1/service-availability", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) > 0
    portal = next(s for s in data if s["name"] == "TN Government Portal")
    assert portal["status"] == "Operational"
    assert portal["latency_ms"] > 0
    assert portal["uptime_pct"] == 99.95

def test_knowledge_ontology_endpoint(client_auth):
    client, headers = client_auth
    res = client.get("/api/v1/knowledge/ontology", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "categories" in data
    assert len(data["categories"]) == 3
    cve_map = next(c for c in data["categories"] if c["id"] == "ont-cve-mapping")
    assert len(cve_map["items"]) > 0

def test_knowledge_base_endpoint(client_auth):
    client, headers = client_auth
    res = client.get("/api/v1/knowledge/base", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "templates" in data
    assert "School" in data["templates"]
    assert "rules" in data["templates"]["School"]
    assert len(data["templates"]["School"]["rules"]) > 0

def test_statewide_exchange_endpoint(client_auth):
    client, headers = client_auth
    res = client.get("/api/v1/intelligence/statewide-exchange", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "shared_iocs" in data
    assert len(data["shared_iocs"]) > 0
    assert "district_feeds" in data

def test_emergency_crisis_lockdown(client_auth):
    client, headers = client_auth
    
    payload = {
        "reason": "Test critical ransomware outbreak statewide simulation",
        "passcode": "NIRAVAN_LOCKDOWN_CONFIRM"
    }
    res = client.post("/api/v1/mitigation/crisis-lockdown", json=payload, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    
    res_services = client.get("/api/v1/service-availability", headers=headers)
    for s in res_services.json():
        assert s["status"] == "Locked"

def test_copilot_friendly_advisor_responses(client_auth):
    client, headers = client_auth
    
    res1 = client.post("/api/v1/copilot", json={"prompt": "Is it safe to open port 3389?"}, headers=headers)
    assert res1.status_code == 200
    r1 = res1.json()["response"]
    assert "3389" in r1 or "RDP" in r1
    assert "highly dangerous" in r1 or "ஆபத்தானது" in r1
    
    res2 = client.post("/api/v1/copilot", json={"prompt": "How to secure database passwords?"}, headers=headers)
    assert res2.status_code == 200
    r2 = res2.json()["response"]
    assert "MFA" in r2
    assert "கடவுச்சொல்" in r2 or "password" in r2.lower()
    
    res3 = client.post("/api/v1/copilot", json={"prompt": "What if I get a suspicious link?"}, headers=headers)
    assert res3.status_code == 200
    r3 = res3.json()["response"]
    assert "phishing" in r3.lower() or "சந்தேகத்திற்குரிய" in r3
