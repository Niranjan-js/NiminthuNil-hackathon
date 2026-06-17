import datetime
from sqlalchemy.orm import Session
from typing import List, Dict, Any

class DefenseMemory:
    """
    Defense Memory tracks the historical performance of automated mitigations
    (e.g., block_ip, isolate_host) and patterns to ensure that NIRAVAN is
    learning which response strategies succeed and which fail.
    """
    
    @staticmethod
    def record_action(db: Session, pattern: str, action: str, result: str, incident_id: str = None) -> Dict[str, Any]:
        """
        Record a mitigation action execution and its result into the database.
        """
        from main import DefenseMemoryModel
        
        mem = DefenseMemoryModel(
            pattern=pattern,
            action=action,
            result=result,
            incident_id=incident_id,
            timestamp=datetime.datetime.utcnow()
        )
        db.add(mem)
        db.commit()
        db.refresh(mem)
        return {
            "id": mem.id,
            "pattern": mem.pattern,
            "action": mem.action,
            "result": mem.result,
            "timestamp": mem.timestamp.isoformat()
        }

    @staticmethod
    def get_action_success_rate(db: Session, pattern: str, action: str) -> float:
        """
        Compute the success rate of a specific action for a given pattern.
        Returns a float between 0.0 and 1.0. If no history is found, returns 1.0 (optimistic default).
        """
        from main import DefenseMemoryModel
        
        history = db.query(DefenseMemoryModel).filter(
            DefenseMemoryModel.pattern == pattern,
            DefenseMemoryModel.action == action
        ).all()
        
        if not history:
            return 1.0
            
        successes = sum(1 for h in history if h.result == "successful")
        return float(successes) / len(history)

    @staticmethod
    def get_all_memory(db: Session, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve a list of defense memories, sorted by latest first.
        """
        from main import DefenseMemoryModel
        
        memories = db.query(DefenseMemoryModel).order_by(DefenseMemoryModel.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": m.id,
                "pattern": m.pattern,
                "action": m.action,
                "result": m.result,
                "incident_id": m.incident_id,
                "timestamp": m.timestamp.isoformat()
            }
            for m in memories
        ]
