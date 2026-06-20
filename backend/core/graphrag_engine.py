import logging
from typing import Dict, Any, List
from memory.vector_memory import VectorMemory
from graphs.knowledge_graph import KnowledgeGraph
from graphs.attack_graph import AttackGraph

logger = logging.getLogger("niravan.core.graphrag_engine")

class GraphRAGEngine:
    """
    GraphRAG Engine combines vector-based similarity searches from past incidents
    with entity relationship data from the Knowledge Graph and path/risk assessments
    from the Attack Graph to construct a comprehensive context for security analysis.
    """

    @classmethod
    def retrieve_context(cls, db, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieves unified context for a given incident, pulling from vector memory,
        knowledge graph, and attack graph.
        """
        description = incident_data.get("description", "")
        host = incident_data.get("host")
        incident_type = incident_data.get("type", "Generic")
        
        # 1. Retrieve similar historical cases via Vector Memory
        similar_cases = []
        try:
            similar_ids = VectorMemory.find_similar(db, description, top_k=3)
            for inst_id, score in similar_ids:
                # Retrieve the actual incident details and its defense outcome if any
                from main import IncidentModel, DefenseMemoryModel
                past_inc = db.query(IncidentModel).filter(IncidentModel.id == inst_id).first()
                past_actions = db.query(DefenseMemoryModel).filter(DefenseMemoryModel.incident_id == inst_id).all()
                
                actions_taken = []
                for action in past_actions:
                    actions_taken.append({
                        "action": action.action,
                        "result": action.result,
                        "effectiveness_score": getattr(action, "effectiveness_score", None)
                    })
                
                if past_inc:
                    similar_cases.append({
                        "incident_id": past_inc.id,
                        "title": past_inc.title,
                        "type": past_inc.type,
                        "description": past_inc.description,
                        "similarity_score": score,
                        "actions_taken": actions_taken
                    })
        except Exception as e:
            logger.error(f"GraphRAG: failed to retrieve vector memory context: {e}")

        # 2. Retrieve entity context from Knowledge Graph
        kg_context = {}
        if host:
            try:
                kg = KnowledgeGraph(db)
                kg_context = kg.get_entity_context(host)
            except Exception as e:
                logger.error(f"GraphRAG: failed to retrieve knowledge graph context: {e}")

        # 3. Retrieve attack path and risk assessment from Attack Graph
        attack_path_info = {}
        if host:
            try:
                graph = AttackGraph.build_from_db(db)
                attack_path_info = AttackGraph.find_attack_path(graph, "internet", host)
            except Exception as e:
                logger.error(f"GraphRAG: failed to retrieve attack graph context: {e}")

        # 4. Synthesize all retrieved context into a single structured payload
        context = {
            "incident_id": incident_data.get("id"),
            "current_incident": {
                "title": incident_data.get("title"),
                "type": incident_type,
                "description": description,
                "host": host,
                "user": incident_data.get("user")
            },
            "similar_past_incidents": similar_cases,
            "knowledge_graph_context": kg_context,
            "attack_path_analysis": attack_path_info
        }
        
        logger.info(f"GraphRAG context compiled successfully for incident {incident_data.get('id')}.")
        return context
