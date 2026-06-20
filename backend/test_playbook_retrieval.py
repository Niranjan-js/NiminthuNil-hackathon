import pytest
from main import Base, engine, SessionLocal, seed_database
from memory.vector_memory import VectorMemory
from memory.defense_memory import EnhancedDefenseMemory
from agents.mitigation_agent import MitigationAgent

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()

@pytest.mark.asyncio
async def test_playbook_retrieval_and_prioritization():
    db = SessionLocal()
    try:
        # 1. Create and store a past incident to serve as historical context
        past_incident_id = "inc-9999"
        past_desc = "Unauthorized SSH login attempt from external IP 192.168.10.50"
        
        # Add to vector memory
        VectorMemory.add_incident(db, past_incident_id, past_desc)
        
        # Record a successful defense memory for this specific incident
        # so that it registers as a successful playbook
        EnhancedDefenseMemory.record_with_effectiveness(
            db,
            pattern="SSH Brute Force",
            action="block_ip",
            result="successful",
            effectiveness_score=1.0,
            incident_id=past_incident_id
        )
        
        # 2. Setup the current incident and its analysis
        new_incident_desc = "Multiple SSH failures from 192.168.10.50"
        
        # Query for similar past incidents using vector memory
        similar_ids = VectorMemory.find_similar(db, new_incident_desc, top_k=3)
        similar_incidents = [{"incident_id": item[0], "similarity": item[1]} for item in similar_ids]
        
        # We expect our past incident to be matched as highly similar
        assert any(x["incident_id"] == past_incident_id for x in similar_incidents)
        
        # Prepare the observation and analysis dicts
        observation = {
            "incident": {
                "id": "inc-8888",
                "description": new_incident_desc,
                "type": "SSH Brute Force",
                "host": "server-1"
            },
            "similar_past_incidents": similar_incidents,
            "ip_address": "192.168.10.50",
            "host": "server-1"
        }
        
        analysis = {
            "attack_pattern": "SSH Brute Force",
            "technique_id": "T1110",
            "severity": "medium",
            "confidence": 0.88,
            "recommended_actions": ["isolate_host"] # default recommendation is different!
        }
        
        # 3. Generate the plan using the MitigationAgent
        mitigation_agent = MitigationAgent()
        plan = await mitigation_agent.generate_plan(db, analysis, observation)
        
        # 4. Assertions
        actions = plan.get("actions", [])
        assert len(actions) > 0
        
        # Check that 'block_ip' (which was the successful action in the similar past incident)
        # is placed at the top of the actions (priority 1), overriding the default "isolate_host"
        first_action = actions[0]
        assert first_action["type"] == "block_ip"
        assert first_action["priority"] == 1
        
    finally:
        db.close()
