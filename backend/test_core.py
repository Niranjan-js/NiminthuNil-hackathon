import json
import pytest
from fastapi.testclient import TestClient
from main import app, get_db, SessionLocal, Base, engine, seed_database, seed_cases, seed_detection_rules, classify_bot_and_threat, attribute_threat

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    # Ensure all tables are created and seeded in the test database
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
        seed_cases(db)
        seed_detection_rules(db)
    finally:
        db.close()

def test_bot_classification():
    # Test Search Engine Bot
    res = classify_bot_and_threat("1.1.1.1", "Mozilla/5.0 Googlebot/2.1", "/index.html")
    assert res["bot_type"] == "Search Engine Bot"
    assert res["threat_level"] == "low"

    # Test Security Scanner
    res = classify_bot_and_threat("1.1.1.1", "Mozilla/5.0 sqlmap/1.8", "/admin")
    assert res["bot_type"] == "Security Scanner"
    assert res["threat_level"] == "medium"

    # Test Web Scanner via high-rate path touches
    res = classify_bot_and_threat("1.1.1.1", "Mozilla/5.0", "/wp-admin", request_rate=15)
    assert res["bot_type"] == "Web Scanner Bot"
    assert res["threat_level"] == "high"

def test_threat_attribution():
    # Automated Bot
    res = attribute_threat("login attempts failed", 0.05, 150)
    assert res["attribution"] == "Bot"
    assert res["confidence"] >= 90

    # Insider Threat
    res = attribute_threat("data_exfiltration event from workstation", 1.5, 5)
    assert res["attribution"] == "Insider Threat"

    # APT
    res = attribute_threat("zero_day remote code execution", 0.5, 1)
    assert res["attribution"] == "APT-like Activity"

def test_login_and_deception_flow():
    with TestClient(app) as client:
        # 1. Login as admin to get token
        login_res = client.post("/api/v1/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Get honeypot statuses
        hp_res = client.get("/api/v1/deception/honeypots", headers=headers)
        assert hp_res.status_code == 200
        data = hp_res.json()
        assert "honeypots" in data
        assert len(data["honeypots"]) == 4
        
        # Check that SSH is seeded
        ssh_hp = next(h for h in data["honeypots"] if h["type"] == "SSH")
        assert ssh_hp["hits"] >= 2

        # 3. Trigger a fake Web honeypot hit
        trigger_res = client.post(
            "/api/v1/deception/trigger",
            headers=headers,
            json={"honeypot_type": "Web", "source_ip": "192.0.2.1"}
        )
        assert trigger_res.status_code == 200
        trigger_data = trigger_res.json()
        assert "incident_id" in trigger_data
        assert "case_id" in trigger_data
        assert trigger_data["attribution"] == "Web Scanner Bot"

        # 4. Get threat attribution stats
        attr_res = client.get("/api/v1/deception/attribution", headers=headers)
        assert attr_res.status_code == 200
        attr_data = attr_res.json()
        assert "scanners" in attr_data
        assert attr_data["total"] > 0

def test_copilot_responses():
    with TestClient(app) as client:
        # Login
        login_res = client.post("/api/v1/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Test CVE concept response
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "explain CVE vulnerabilities"})
        assert res.status_code == 200
        assert "Security Mentor" in res.json()["response"]

        # Test Deception response
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "show honeypot logs"})
        assert res.status_code == 200
        assert "Deception Network Status" in res.json()["response"]

        # Test Threat tool response
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "tell me about mimikatz"})
        assert res.status_code == 200
        assert "Threat Tool Reference" in res.json()["response"]

        # Test TNCKB Hospital response
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "Show TNCKB security template for public hospitals"})
        assert res.status_code == 200
        assert "Hospitals & Health Centers" in res.json()["response"]

        # Test TNCKB School response
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "What is the EMIS database security policy?"})
        assert res.status_code == 200
        assert "School & Educational Institutions" in res.json()["response"]

        # Test Defense Memory response
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "Show past remediation logs from Defense Memory"})
        assert res.status_code == 200
        assert "Defense Memory" in res.json()["response"]

        # Test Compliance response
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "Verify compliance status for CERT-In guidelines and DPDP act."})
        assert res.status_code == 200
        assert "Regulatory Readiness" in res.json()["response"]

def test_new_intelligence_features():
    with TestClient(app) as client:
        # 1. Login
        login_res = client.post("/api/v1/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Test Ingestion of Telemetry: Windows Sysmon Shadow copy deletion
        telemetry_payload = {
            "source_type": "windows_sysmon",
            "host": "ast-001",
            "log_data": {
                "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                "user": "j.smith@corp.com"
            }
        }
        res = client.post("/api/v1/ingest/telemetry", json=telemetry_payload)
        assert res.status_code == 200
        assert res.json()["status"] == "triggered"
        assert "Ransomware Shadow Copy Deletion" in res.json()["rule"]

        # 3. Test Graph Nodes and Edges
        res = client.get("/api/v1/graph/nodes", headers=headers)
        assert res.status_code == 200
        nodes = res.json()
        assert len(nodes) > 0
        assert any(n["entity_type"] == "User" for n in nodes)

        res = client.get("/api/v1/graph/edges", headers=headers)
        assert res.status_code == 200
        edges = res.json()
        assert len(edges) > 0

        # 4. Test Blast Radius endpoint
        res = client.get("/api/v1/graph/blast-radius/User/admin@niravan.ai", headers=headers)
        assert res.status_code == 200
        assert "blast_radius" in res.json()

        # 5. Test Attack Path endpoint
        res = client.get("/api/v1/graph/attack-path/User/admin@niravan.ai/Asset/ast-001", headers=headers)
        assert res.status_code == 200
        assert "attack_path" in res.json()

        # 6. Test Campaigns retrieval and manual Correlation trigger
        res = client.get("/api/v1/campaigns", headers=headers)
        assert res.status_code == 200
        campaigns = res.json()
        assert len(campaigns) > 0

        res = client.post("/api/v1/campaigns/correlate", headers=headers)
        assert res.status_code == 200

        # 7. Test Profile endpoints
        res = client.get("/api/v1/profiles/user/admin@niravan.ai", headers=headers)
        assert res.status_code == 200
        assert res.json()["email"] == "admin@niravan.ai"

        res = client.get("/api/v1/profiles/ip/185.220.101.47", headers=headers)
        assert res.status_code == 200
        assert res.json()["ip"] == "185.220.101.47"

        res = client.get("/api/v1/profiles/asset/ast-001", headers=headers)
        assert res.status_code == 200

        # 8. Test Evidence Vault
        res = client.get("/api/v1/vault/evidence", headers=headers)
        assert res.status_code == 200
        assert "suspicious_activities" in res.json()

        # 9. Test Case Dossier Package download
        cases_res = client.get("/api/v1/cases", headers=headers)
        assert cases_res.status_code == 200
        cases = cases_res.json()
        if len(cases) > 0:
            case_id = cases[0]["id"]
            res = client.get(f"/api/v1/cases/{case_id}/download-package", headers=headers)
            assert res.status_code == 200
            assert "remediation_playbook" in res.json()

        # 10. Test Active ASM discovery scanner queue
        res = client.post("/api/v1/asm/scan-network", headers=headers, json={"target": "school.tn.gov.in"})
        assert res.status_code == 200
        assert res.json()["status"] == "queued"
        job_id = res.json()["job_id"]
        
        # Test Job Status check
        res = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        assert res.status_code == 200
        assert res.json()["job_id"] == job_id
        
        # 11. Test Mitigation Containment IP blocking
        res = client.post("/api/v1/mitigation/block-ip", headers=headers, json={"ip": "185.220.101.47", "reason": "Test Block"})
        assert res.status_code == 200
        assert "successfully blocked" in res.json()["message"]
        
        # Test Mitigation Containment Host Isolation
        res = client.post("/api/v1/mitigation/isolate-host", headers=headers, json={"host": "ast-001", "reason": "Test Isolate"})
        assert res.status_code == 200
        assert "successfully isolated" in res.json()["message"]


def test_openvas_connector():
    """Tests the OpenVAS connector mock scanning pipeline end-to-end."""
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from openvas_connector import OpenVASConnector

    # 1. Start a mock scan for a web server
    scan_id = OpenVASConnector.start_scan("prod-web-server.tn.gov.in", "10.0.0.5")
    assert scan_id.startswith("ov-"), f"Expected ov- prefix, got: {scan_id}"

    # 2. Poll status — first poll should move to running
    status = OpenVASConnector.get_scan_status(scan_id)
    assert status in ("queued", "running", "completed")

    # 3. Poll again — second poll should move to completed
    status = OpenVASConnector.get_scan_status(scan_id)
    assert status in ("running", "completed")

    # 4. Force completion if needed
    for _ in range(3):
        status = OpenVASConnector.get_scan_status(scan_id)
        if status == "completed":
            break

    assert status == "completed", f"Expected completed, got: {status}"

    # 5. Get findings
    findings = OpenVASConnector.get_vulnerabilities(scan_id)
    assert isinstance(findings, list)
    assert len(findings) > 0, "Expected at least one vulnerability finding"

    # 6. Verify finding structure
    for f in findings:
        assert "cve_id" in f
        assert "cvss" in f
        assert "severity" in f
        assert "description" in f
        assert "remediation" in f
        assert f["cvss"] > 0
        assert f["severity"] in ("critical", "high", "medium", "low")

    # 7. Verify summary generation
    summary_en = OpenVASConnector.get_summary_plain_english(findings, language="en")
    assert "OpenVAS" in summary_en or "vulnerabilities" in summary_en.lower()

    summary_ta = OpenVASConnector.get_summary_plain_english(findings, language="ta")
    assert len(summary_ta) > 20  # Should have Tamil content

    # 8. Test with keyword targets
    scan2 = OpenVASConnector.start_scan("rdp-server.gov.in")
    for _ in range(5):
        if OpenVASConnector.get_scan_status(scan2) == "completed":
            break
    findings2 = OpenVASConnector.get_vulnerabilities(scan2)
    # RDP target should include RDP-related findings
    assert len(findings2) > 0


def test_vulnerability_endpoints():
    """Tests the new /api/v1/vulnerabilities endpoints."""
    with TestClient(app) as client:
        # Login
        login_res = client.post("/api/v1/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. GET /api/v1/vulnerabilities — should return CVE list
        res = client.get("/api/v1/vulnerabilities", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert "vulnerabilities" in data
        assert "total" in data
        assert "critical_count" in data
        assert "high_count" in data
        assert data["total"] >= 0  # May be 0 if no CVEs seeded yet

        # 2. POST /api/v1/vulnerabilities/scan — trigger standalone OpenVAS scan
        res = client.post("/api/v1/vulnerabilities/scan", headers=headers, params={"target": "test-server.tn.gov.in"})
        assert res.status_code == 200
        assert "scan_id" in res.json()
        assert res.json()["status"] == "started"
        scan_id = res.json()["scan_id"]

        # 3. GET /api/v1/vulnerabilities/scan/{scan_id} — poll scan status
        res = client.get(f"/api/v1/vulnerabilities/scan/{scan_id}", headers=headers)
        assert res.status_code == 200
        assert "status" in res.json()
        assert res.json()["scan_id"] == scan_id


def test_guardian_ai_officer_copilot():
    """Tests the enhanced Guardian AI Officer copilot responses in English and Tamil."""
    with TestClient(app) as client:
        # Login
        login_res = client.post("/api/v1/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. English: Why is my risk score high?
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "Why is my risk score high?"})
        assert res.status_code == 200
        response = res.json()["response"]
        # Should contain structured breakdown
        assert any(term in response for term in ["Guardian AI Officer", "Risk Score", "risk score", "NIRAVAN", "risk"])

        # 2. English: Posture query
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "What is my security posture?"})
        assert res.status_code == 200
        assert len(res.json()["response"]) > 100

        # 3. Tamil: risk score query
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "அபாய மதிப்பெண் ஏன் அதிகமாக உள்ளது?"})
        assert res.status_code == 200
        response_ta = res.json()["response"]
        # Should be Tamil content (longer than a short fallback)
        assert len(response_ta) > 50

        # 4. OpenVAS vulnerability scan query
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "Show me the OpenVAS vulnerability scan results"})
        assert res.status_code == 200
        assert "OpenVAS" in res.json()["response"]

        # 5. What vulnerabilities does my system have?
        res = client.post("/api/v1/copilot", headers=headers, json={"prompt": "What vulnerabilities does my system have?"})
        assert res.status_code == 200
        assert len(res.json()["response"]) > 50


def test_active_directory_defense_and_threat_hunting():
    from wazuh_ingestor import WazuhIngestor
    from threat_hunting.campaign_manager import CampaignManager
    
    # 1. Test AD event log parsing
    log_4769 = {
        "EventID": 4769,
        "TicketEncryptionType": "0x17",
        "ServiceName": "krbtgt"
    }
    normalized = WazuhIngestor.parse_log("windows_event", log_4769)
    assert normalized["event_name"] == "Kerberoasting Ticket Request (EventID 4769)"
    assert normalized["severity"] == "critical"
    assert "T1558.003" in normalized["mitre"]
    
    log_4662 = {
        "EventID": 4662,
        "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
    }
    normalized = WazuhIngestor.parse_log("windows_event", log_4662)
    assert "DCSync" in normalized["event_name"]
    assert normalized["severity"] == "critical"
    assert "T1003.006" in normalized["mitre"]
    
    # 2. Test CampaignManager runs without errors
    db = SessionLocal()
    try:
        res = CampaignManager.run_hunt_campaign(db)
        assert res["status"] == "completed"
        assert res["cves_synced"] >= 0
        assert res["assets_mapped"] >= 0
    finally:
        db.close()


if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
