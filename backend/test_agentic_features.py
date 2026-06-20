import pytest
import datetime
from main import Base, engine, SessionLocal, seed_database, AssetModel, IOCModel, ServiceAvailabilityModel
from core.graphrag_engine import GraphRAGEngine
from agents.meta_agent import MetaAgent
from agents.verification_agent import VerificationAgent
from core.rollback_manager import RollbackManager
from core.planner_agent import PlannerAgent

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Clear out any existing state
        db.query(AssetModel).delete()
        db.query(IOCModel).delete()
        db.query(ServiceAvailabilityModel).delete()
        db.commit()
        seed_database(db)
    finally:
        db.close()

def test_meta_agent_selection():
    # Low severity -> only threat_analyst, mitigation_agent
    agents_low = MetaAgent.select_agents_to_run("low", "Port Scan")
    assert "threat_analyst" in agents_low
    assert "mitigation_agent" in agents_low
    assert "forensics_agent" not in agents_low
    
    # Critical severity or ransomware -> full swarm
    agents_crit = MetaAgent.select_agents_to_run("critical", "Ransomware")
    assert "threat_analyst" in agents_crit
    assert "mitigation_agent" in agents_crit
    assert "impact_agent" in agents_crit
    assert "compliance_agent" in agents_crit
    assert "hunter_agent" in agents_crit
    assert "forensics_agent" in agents_crit

def test_graphrag_engine():
    db = SessionLocal()
    try:
        incident_data = {
            "id": "inc-test-graphrag",
            "title": "Suspected SSH Brute Force",
            "type": "Brute Force",
            "description": "Multiple login failures on Collectorate-Server",
            "host": "Collectorate-Server",
            "user": "root"
        }
        
        context = GraphRAGEngine.retrieve_context(db, incident_data)
        assert context["incident_id"] == "inc-test-graphrag"
        assert "knowledge_graph_context" in context
        assert "attack_path_analysis" in context
        assert "similar_past_incidents" in context
    finally:
        db.close()

def test_verification_agent():
    db = SessionLocal()
    try:
        # Setup pre-requisite for testing block_ip verification
        # 1. Test block_ip verify failure
        v_fail = VerificationAgent.verify_remediation(db, "block_ip", {"ip_address": "192.168.99.99"})
        assert v_fail["success"] is False
        assert "FAILED" in v_fail["details"]

        # 2. Add to blocklist and verify success
        ioc = IOCModel(type="IP", indicator="192.168.99.99", actor="Unknown", confidence=90, lastSeen="now", threat="blocked")
        db.add(ioc)
        db.commit()
        
        v_success = VerificationAgent.verify_remediation(db, "block_ip", {"ip_address": "192.168.99.99"})
        assert v_success["success"] is True
        assert "successfully added" in v_success["details"]
        
    finally:
        db.close()

def test_rollback_manager():
    db = SessionLocal()
    try:
        # 1. Test rollback of block_ip
        ioc = IOCModel(type="IP", indicator="10.10.10.10", actor="Unknown", confidence=90, lastSeen="now", threat="blocked")
        db.add(ioc)
        db.commit()
        
        # Verify it exists
        assert db.query(IOCModel).filter(IOCModel.indicator == "10.10.10.10").first() is not None
        
        # Rollback
        rollback_res = RollbackManager.execute_rollback(db, "block_ip", {"ip_address": "10.10.10.10"})
        assert rollback_res["success"] is True
        
        # Verify it is removed
        assert db.query(IOCModel).filter(IOCModel.indicator == "10.10.10.10").first() is None
        
        # 2. Test rollback of isolate_host
        asset = db.query(AssetModel).filter(AssetModel.name == "Collectorate-Server").first()
        if asset:
            asset.status = "Isolated"
            db.commit()
            
            rollback_res = RollbackManager.execute_rollback(db, "isolate_host", {"hostname": "Collectorate-Server"})
            assert rollback_res["success"] is True
            
            db.refresh(asset)
            assert asset.status == "Active"
            
    finally:
        db.close()

@pytest.mark.asyncio
async def test_planner_agent_run_cycle_integration():
    db = SessionLocal()
    try:
        incident_data = {
            "id": "inc-test-integration",
            "title": "Brute Force Attack on Web Server",
            "type": "Brute Force",
            "description": "Repeated unauthorized access attempts observed from IP 198.51.100.42",
            "host": "Collectorate-Server",
            "user": "admin",
            "ip_address": "198.51.100.42"
        }
        
        planner = PlannerAgent(db)
        result = await planner.run_cycle(incident_data)
        
        assert result["status"] in ["completed", "awaiting_approval"]
        assert "consensus" in result
        assert "explanation" in result
        assert "verification" in result
    finally:
        db.close()
