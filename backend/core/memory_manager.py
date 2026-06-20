import logging
from typing import Dict, Any, List
from memory.vector_memory import VectorMemory
from memory.defense_memory import EnhancedDefenseMemory

logger = logging.getLogger("niravan.core.memory_manager")

class MemoryManager:
    """
    Unified memory manager providing single-point operations for
    TF-IDF semantic indexing and defense action reinforcement learning.
    """

    def __init__(self, db):
        self.db = db

    def store_incident(self, incident_data: Dict[str, Any]) -> bool:
        """
        Add incident description to TF-IDF vector database.
        """
        incident_id = incident_data.get("id")
        text = f"Title: {incident_data.get('title')}. Type: {incident_data.get('type')}. Description: {incident_data.get('description')}"
        if incident_id and text:
            return VectorMemory.add_incident(self.db, incident_id, text)
        return False

    def find_similar_incidents(self, description: str, top_k: int = 3) -> List[Any]:
        """
        Find top-k similar incidents from semantic vector memory.
        """
        return VectorMemory.find_similar(self.db, description, top_k)

    def get_best_action(self, attack_pattern: str) -> str:
        """
        Get the most successful historical action type for an attack pattern.
        """
        recs = EnhancedDefenseMemory.get_recommended_actions(self.db, attack_pattern)
        if recs:
            # Recommendations are sorted by success rate descending
            return recs[0]["action"]
        return ""

    def record_outcome(self, pattern: str, action: str, result: str, effectiveness: float, incident_id: str = None) -> Dict[str, Any]:
        """
        Record a defense action outcome and its reinforcement score.
        """
        return EnhancedDefenseMemory.record_with_effectiveness(
            self.db, pattern, action, result, effectiveness, incident_id
        )

    def get_memory_summary(self) -> Dict[str, Any]:
        """
        Returns statistics regarding vector memory and defense action performance.
        """
        try:
            from main import VectorMemoryModel, DefenseMemoryModel
            
            total_indexed = self.db.query(VectorMemoryModel).count()
            total_actions = self.db.query(DefenseMemoryModel).count()
            
            # Find most common attack patterns in memory
            memories = self.db.query(DefenseMemoryModel).all()
            pattern_counts = {}
            action_success = {}
            
            for m in memories:
                pattern_counts[m.pattern] = pattern_counts.get(m.pattern, 0) + 1
                
                # Action success mapping
                if m.action not in action_success:
                    action_success[m.action] = {"success": 0, "total": 0}
                action_success[m.action]["total"] += 1
                if m.result == "successful":
                    action_success[m.action]["success"] += 1
                    
            top_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            
            effectiveness_map = {}
            for act, stats in action_success.items():
                effectiveness_map[act] = round(stats["success"] / stats["total"], 2)
                
            return {
                "total_indexed_incidents": total_indexed,
                "total_defense_records": total_actions,
                "top_attack_patterns": dict(top_patterns),
                "action_effectiveness": effectiveness_map
            }
        except Exception as e:
            logger.error(f"Error building memory summary: {e}")
            return {
                "total_indexed_incidents": 0,
                "total_defense_records": 0,
                "top_attack_patterns": {},
                "action_effectiveness": {}
            }
