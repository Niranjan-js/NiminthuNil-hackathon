import pytest
import json
from fastapi.testclient import TestClient
from main import app, Base, engine, SessionLocal, seed_database, seed_cases, IncidentModel, CaseModel, LocalNodeAuditModel

@pytest.fixture(scope="module")
def client_auth():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Clear existing local audits to isolate tests
        db.query(LocalNodeAuditModel).delete()
        db.query(IncidentModel).filter(IncidentModel.type == "LOCAL_NODE_AUDIT").delete()
        db.query(CaseModel).filter(CaseModel.title.like("%Local Node%")).delete()
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

def test_local_node_scan(client_auth):
    client, headers = client_auth
    
    # Trigger scan for Hospital
    res = client.post("/api/v1/local-node/scan", json={"department": "Hospital"}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    
    assert data["status"] == "completed"
    assert "audit_id" in data
    assert data["department"] == "Hospital"
    assert data["risk_score"] == 100.0
    assert data["critical_findings"] == 4
    assert data["citizen_impact"] == 5000
    assert len(data["findings"]) > 0
    
    # Verify findings structure and bilingual keys
    first_finding = data["findings"][0]
    assert "module" in first_finding
    assert "severity" in first_finding
    assert "issue" in first_finding
    assert "tamil_issue" in first_finding

def test_local_node_sync(client_auth):
    client, headers = client_auth
    
    # 1. Trigger scan to generate an audit
    res_scan = client.post("/api/v1/local-node/scan", json={"department": "Hospital"}, headers=headers)
    assert res_scan.status_code == 200
    audit_id = res_scan.json()["audit_id"]
    
    # 2. Sync to SOC
    res_sync = client.post("/api/v1/local-node/sync", json={"audit_id": audit_id}, headers=headers)
    assert res_sync.status_code == 200
    sync_data = res_sync.json()
    assert sync_data["status"] == "success"
    assert "incident_id" in sync_data
    assert "case_id" in sync_data
    
    # 3. Verify in database
    db = SessionLocal()
    try:
        incident = db.query(IncidentModel).filter(IncidentModel.id == sync_data["incident_id"]).first()
        assert incident is not None
        assert incident.title == "Hospital Local Node Audit Alert"
        assert incident.severity == "critical"
        assert incident.affected_citizens == 5000
        assert incident.affected_departments == "Hospital"
        
        case = db.query(CaseModel).filter(CaseModel.id == sync_data["case_id"]).first()
        assert case is not None
        assert case.title == "Case: Hospital Local Node Audit Alert"
        assert case.severity == "critical"
        assert case.affected_citizens == 5000
        assert case.affected_departments == "Hospital"
        
        audit = db.query(LocalNodeAuditModel).filter(LocalNodeAuditModel.id == audit_id).first()
        assert audit.sync_status == "synced"
    finally:
        db.close()

def test_local_node_audits_list(client_auth):
    client, headers = client_auth
    
    # Trigger a scan for School
    res_scan = client.post("/api/v1/local-node/scan", json={"department": "School"}, headers=headers)
    assert res_scan.status_code == 200
    audit_id = res_scan.json()["audit_id"]
    
    # Get audits list
    res_list = client.get("/api/v1/local-node/audits", headers=headers)
    assert res_list.status_code == 200
    audits = res_list.json()
    assert len(audits) > 0
    
    school_audit = next(a for a in audits if a["audit_id"] == audit_id)
    assert school_audit["department"] == "School"
    # School findings in main.py:
    # SBOM: jquery (Medium) -> 1 Medium
    # Network: Port 23 (High) -> 1 High
    # Credential: secrets.yml (High) -> 1 High
    # PII: Student Records (High) -> 1 High
    # Threat Log: Service Manipulation (Medium) -> 1 Medium
    # Total: High = 3, Medium = 2.
    # Risk Score: min(100, 3*10 + 2*5) = 40.
    assert school_audit["risk_score"] == 40.0
    assert school_audit["citizen_impact"] == 3000

def test_statewide_correlation(client_auth):
    client, headers = client_auth
    
    # Clear existing audits first
    db = SessionLocal()
    try:
        db.query(LocalNodeAuditModel).delete()
        db.commit()
    finally:
        db.close()
        
    # Trigger scan for Hospital (contains Port 445 public exposure)
    res_hosp = client.post("/api/v1/local-node/scan", json={"department": "Hospital"}, headers=headers)
    assert res_hosp.status_code == 200
    
    # Trigger scan for Police (contains Port 445 public exposure)
    res_police = client.post("/api/v1/local-node/scan", json={"department": "Police"}, headers=headers)
    assert res_police.status_code == 200
    
    # Call correlation endpoint
    res_corr = client.get("/api/v1/local-node/statewide-correlation", headers=headers)
    assert res_corr.status_code == 200
    corr_data = res_corr.json()
    
    assert corr_data["total_patterns"] > 0
    
    # Verify Port 445 pattern is detected
    smb_advisory = next(
        adv for adv in corr_data["advisories"] 
        if "Port 445 (SMB) public exposure" in adv["vulnerability"]
    )
    assert smb_advisory["pattern_detected"] is True
    assert "Hospital" in smb_advisory["affected_organizations"]
    assert "Police" in smb_advisory["affected_organizations"]
    assert smb_advisory["potential_attack_surface"] == "Exposed Network Services"
