import datetime
import logging
from typing import List, Dict, Any

logger = logging.getLogger("niravan.memory.defense_memory")

class EnhancedDefenseMemory:
    """
    Enhanced Defense Memory for recording the outcome of defensive actions,
    ranking future actions, and retrieving success rates based on reinforcement feedback.
    """

    @staticmethod
    def record_with_effectiveness(db, pattern: str, action: str, result: str, effectiveness_score: float, incident_id: str = None) -> Dict[str, Any]:
        """
        Record a mitigation action outcome along with an effectiveness score (0.0 - 1.0).
        """
        try:
            from main import DefenseMemoryModel
            
            # Map effectiveness to result string if not already done
            result_str = result or ("successful" if effectiveness_score >= 0.7 else "failed")
            
            mem = DefenseMemoryModel(
                pattern=pattern,
                action=action,
                result=result_str,
                incident_id=incident_id,
                lesson=f"Effectiveness score: {effectiveness_score}",
                timestamp=datetime.datetime.utcnow()
            )
            # Store effectiveness_score dynamically if the field is present, else store it in 'lesson'
            if hasattr(mem, 'effectiveness_score'):
                setattr(mem, 'effectiveness_score', effectiveness_score)
                
            db.add(mem)
            db.commit()
            db.refresh(mem)
            logger.info(f"Recorded defense memory for action '{action}' against pattern '{pattern}' with score {effectiveness_score}")
            return {
                "id": mem.id,
                "pattern": mem.pattern,
                "action": mem.action,
                "result": mem.result,
                "effectiveness_score": effectiveness_score,
                "timestamp": mem.timestamp.isoformat()
            }
        except Exception as e:
            logger.error(f"Error recording defense memory: {e}")
            return {}

    @staticmethod
    def get_action_success_rate(db, pattern: str, action: str) -> float:
        """
        Retrieve success rate for a specific action against a specific pattern.
        Returns a float between 0.0 and 1.0. If no history is found, returns 1.0 (optimistic default).
        """
        try:
            from main import DefenseMemoryModel
            
            history = db.query(DefenseMemoryModel).filter(
                DefenseMemoryModel.pattern == pattern,
                DefenseMemoryModel.action == action
            ).all()
            
            if not history:
                return 1.0
                
            # Compute based on effectiveness_score if present, else on result string
            total_score = 0.0
            count = 0
            for h in history:
                if hasattr(h, 'effectiveness_score') and getattr(h, 'effectiveness_score') is not None:
                    total_score += getattr(h, 'effectiveness_score')
                else:
                    total_score += 1.0 if h.result == "successful" else 0.0
                count += 1
                
            return total_score / count
        except Exception as e:
            logger.error(f"Error retrieving action success rate: {e}")
            return 1.0

    @classmethod
    def rank_actions(cls, db, pattern: str, actions_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Rank a list of action dictionaries:
        `[{'type': 'block_ip', 'params': {...}, 'reason': '...'}]`
        Sorts them in descending order based on historical success rate.
        """
        try:
            ranked_actions = []
            for action_dict in actions_list:
                action_type = action_dict.get("type", "")
                success_rate = cls.get_action_success_rate(db, pattern, action_type)
                
                # Copy action dict and attach success rate
                action_copy = dict(action_dict)
                action_copy["estimated_success_rate"] = success_rate
                ranked_actions.append(action_copy)
                
            # Sort by success rate descending
            ranked_actions.sort(key=lambda x: x.get("estimated_success_rate", 1.0), reverse=True)
            return ranked_actions
        except Exception as e:
            logger.error(f"Error ranking actions: {e}")
            return actions_list

    @classmethod
    def get_recommended_actions(cls, db, attack_pattern: str) -> List[Dict[str, Any]]:
        """
        Retrieve the top 3 historically successful actions for a given attack pattern.
        """
        try:
            from main import DefenseMemoryModel
            
            history = db.query(DefenseMemoryModel).filter(
                DefenseMemoryModel.pattern == attack_pattern
            ).all()
            
            if not history:
                return []
                
            # Group by action and calculate average success rates
            action_stats = {}
            for h in history:
                action = h.action
                if action not in action_stats:
                    action_stats[action] = {"total": 0.0, "count": 0}
                
                if hasattr(h, 'effectiveness_score') and getattr(h, 'effectiveness_score') is not None:
                    val = getattr(h, 'effectiveness_score')
                else:
                    val = 1.0 if h.result == "successful" else 0.0
                
                action_stats[action]["total"] += val
                action_stats[action]["count"] += 1
                
            recommendations = []
            for action, stats in action_stats.items():
                avg_score = stats["total"] / stats["count"]
                recommendations.append({
                    "action": action,
                    "success_rate": avg_score,
                    "execution_count": stats["count"]
                })
                
            recommendations.sort(key=lambda x: x["success_rate"], reverse=True)
            return recommendations[:3]
        except Exception as e:
            logger.error(f"Error getting recommended actions: {e}")
            return []

    @staticmethod
    def get_all_memory(db, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve a list of defense memories, sorted by latest first.
        """
        try:
            from main import DefenseMemoryModel
            
            memories = db.query(DefenseMemoryModel).order_by(DefenseMemoryModel.timestamp.desc()).limit(limit).all()
            out = []
            for m in memories:
                eff = getattr(m, 'effectiveness_score', None) if hasattr(m, 'effectiveness_score') else None
                out.append({
                    "id": m.id,
                    "pattern": m.pattern,
                    "action": m.action,
                    "result": m.result,
                    "effectiveness_score": eff,
                    "incident_id": m.incident_id,
                    "timestamp": m.timestamp.isoformat()
                })
            return out
        except Exception as e:
            logger.error(f"Error getting all memory: {e}")
            return []
