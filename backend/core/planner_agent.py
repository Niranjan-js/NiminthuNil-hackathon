import logging
import datetime
from typing import Dict, Any, List

from memory.defense_memory import EnhancedDefenseMemory
from core.memory_manager import MemoryManager
from graphs.knowledge_graph import KnowledgeGraph
from agents.threat_analyst import ThreatAnalystAgent
from agents.mitigation_agent import MitigationAgent
from core.validator_agent import ValidatorAgent
from tools.block_ip_tool import BlockIPTool
from tools.isolate_host_tool import IsolateHostTool
from core.graphrag_engine import GraphRAGEngine
from agents.meta_agent import MetaAgent
from agents.verification_agent import VerificationAgent
from core.rollback_manager import RollbackManager

logger = logging.getLogger("niravan.core.planner_agent")

class PlannerAgent:
    """
    The central autonomous SOC Planner Agent implementing a ReAct loop.
    Coordinate observations, AI analysis, response planning, validation,
    execution, verification, and feedback learning.
    """
    
    AUTO_EXECUTE_THRESHOLD = 0.90
    HUMAN_APPROVAL_THRESHOLD = 0.70

    def __init__(self, db):
        self.db = db
        self.memory_manager = MemoryManager(db)
        self.knowledge_graph = KnowledgeGraph(db)
        self.threat_analyst = ThreatAnalystAgent()
        self.mitigation_agent = MitigationAgent()
        self.validator_agent = ValidatorAgent(db)

    async def run_cycle(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a complete parallel swarm cycle with Bayesian confidence calibration
        and explainability checklists for a security incident.
        """
        incident_id = incident_data.get("id")
        logger.info(f"Starting Swarm autonomous cycle for incident: {incident_id}")
        
        cycle_result = {
            "incident_id": incident_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "steps": {},
            "status": "pending",
            "actions_taken": [],
            "verification": {},
            "human_approval_required": True,
            "consensus": {},
            "explanation": {}
        }
        
        try:
            # 1. Observe
            logger.info("Step 1: Observe - Enriching incident context via GraphRAG...")
            observation = await self._observe(incident_data)
            cycle_result["steps"]["observe"] = observation
            
            # 2. Concurrently Spawn and Run Specialized Swarm Agents
            logger.info("Step 2: Swarm - Spawning specialist agents...")
            import asyncio
            from agents.hunter_agent import HunterAgent
            from agents.compliance_agent import ComplianceAgent
            from agents.impact_agent import ImpactAgent
            from agents.forensics_agent import ForensicsAgent
            from agents.consensus_agent import ConsensusAgent
            from agents.identity_agent import IdentityAgent
            from agents.cloud_agent import CloudAgent
            from agents.threat_intel_agent import ThreatIntelAgent
            from core.explanation_engine import ExplanationEngine
            
            hunter = HunterAgent()
            compliance_agent = ComplianceAgent()
            impact_agent = ImpactAgent()
            forensics_agent = ForensicsAgent()
            consensus_agent = ConsensusAgent()
            identity_agent = IdentityAgent()
            cloud_agent = CloudAgent()
            intel_agent = ThreatIntelAgent()
            
            # Threat analyst runs first to establish technique context for other agents
            analysis = await self._think(observation)
            cycle_result["steps"]["think"] = analysis
            
            # Meta-Agent: Dynamically select which agents should run
            severity = analysis.get("severity", "low")
            incident_type = incident_data.get("type", "Generic")
            agents_to_run = MetaAgent.select_agents_to_run(severity, incident_type)
            
            # Prepare default/empty results for agents that do not run
            hunter_res = {"status": "skipped", "findings": [], "recommended_investigation": "No active hunt recommended for this severity."}
            impact_res = {"status": "skipped", "citizens_at_risk": 0, "services_at_risk": [], "departments_at_risk": [], "estimated_downtime_hours": 0.0, "financial_impact_lakhs": 0.0}
            compliance_res = {"status": "skipped", "cert_in_reportable": False, "dpdp_notifiable": False, "compliance_actions": []}
            forensics_res = {"status": "skipped", "timeline": [], "forensic_findings": [], "total_events_correlated": 0}
            identity_res = {"status": "skipped", "score": 0.1, "anomaly_type": "None", "recommendations": []}
            cloud_res = {"status": "skipped", "score": 0.1, "cloud_compromise_detected": False}
            intel_res = {"status": "skipped", "score": 0.1, "matched_feed": "None"}
            
            # Run remaining selected specialists concurrently
            ip_address = incident_data.get("ip_address") or incident_data.get("ip")
            host = incident_data.get("host") or "Collectorate-Server"
            user = incident_data.get("user")
            
            tasks = []
            task_keys = []
            
            if "hunter_agent" in agents_to_run:
                tasks.append(asyncio.to_thread(hunter.run_hunt, self.db, incident_data.get("description", ""), analysis.get("technique_id")))
                task_keys.append("hunter")
            if "impact_agent" in agents_to_run:
                tasks.append(asyncio.to_thread(impact_agent.estimate_impact, self.db, incident_data, analysis))
                task_keys.append("impact")
            if "compliance_agent" in agents_to_run:
                tasks.append(asyncio.to_thread(compliance_agent.map_incident, analysis))
                task_keys.append("compliance")
            if "forensics_agent" in agents_to_run:
                tasks.append(asyncio.to_thread(forensics_agent.reconstruct_timeline, self.db, host, user, ip_address))
                task_keys.append("forensics")
                
            # Identity, Cloud, and Intel agents are always executed for comprehensive coverage
            tasks.append(asyncio.to_thread(identity_agent.analyze_identity_anomalies, self.db, incident_data))
            task_keys.append("identity")
            tasks.append(asyncio.to_thread(cloud_agent.check_cloud_security, self.db, incident_data))
            task_keys.append("cloud")
            tasks.append(asyncio.to_thread(intel_agent.correlate_threat_intel, self.db, incident_data))
            task_keys.append("intel")
                
            if tasks:
                results = await asyncio.gather(*tasks)
                for key, val in zip(task_keys, results):
                    if key == "hunter":
                        hunter_res = val
                    elif key == "impact":
                        impact_res = val
                    elif key == "compliance":
                        compliance_res = val
                    elif key == "forensics":
                        forensics_res = val
                    elif key == "identity":
                        identity_res = val
                    elif key == "cloud":
                        cloud_res = val
                    elif key == "intel":
                        intel_res = val
            
            # 3. Consensus Engine - Merge all parallel assessments
            consensus = consensus_agent.merge_assessments(
                threat=analysis,
                impact=impact_res,
                compliance=compliance_res,
                hunter=hunter_res,
                forensics=forensics_res,
                identity=identity_res,
                cloud=cloud_res,
                intel=intel_res
            )
            cycle_result["consensus"] = consensus
            cycle_result["steps"]["consensus"] = consensus
            
            # 4. Bayesian Confidence Fusion
            calibrated_confidence = consensus.get("consensus_score", 0.5)
            
            # 5. Plan
            logger.info("Step 5: Plan - Structuring mitigation strategies...")
            plan = await self._plan(analysis, observation)
            cycle_result["steps"]["plan"] = plan
            
            # 6. Validate
            logger.info("Step 6: Validate - Screening action safety...")
            validation = await self._validate(plan, observation, calibrated_confidence)
            cycle_result["steps"]["validate"] = validation
            cycle_result["human_approval_required"] = validation.get("human_approval_required", True)
            
            # 7. Explainability Checklist
            explanation = ExplanationEngine.generate_explanation(
                incident_data=incident_data,
                consensus=consensus,
                confidence=calibrated_confidence,
                validation=validation
            )
            cycle_result["explanation"] = explanation
            cycle_result["steps"]["explain"] = explanation
            
            # 8. Execute
            logger.info("Step 8: Execute - Invoking approved containment actions...")
            execution_results = await self._execute(validation, incident_data)
            cycle_result["actions_taken"] = execution_results
            cycle_result["steps"]["execute"] = execution_results
            
            # 9. Verify
            logger.info("Step 9: Verify - Assessing mitigation efficacy...")
            verification = await self._verify(execution_results, incident_data)
            cycle_result["verification"] = verification
            cycle_result["steps"]["verify"] = verification
            
            # 10. Learn
            logger.info("Step 10: Learn - Writing outcome to reinforcement memory...")
            learning = await self._learn(incident_data, execution_results, verification)
            cycle_result["steps"]["learn"] = learning
            
            cycle_result["status"] = "completed" if not cycle_result["human_approval_required"] else "awaiting_approval"
            logger.info(f"Swarm cycle finished for {incident_id}. Status: {cycle_result['status']}")
            
        except Exception as e:
            logger.error(f"Error executing Swarm cycle for incident {incident_id}: {e}", exc_info=True)
            cycle_result["status"] = "failed"
            cycle_result["error"] = str(e)
            
        return cycle_result

    async def _observe(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the incident with KnowledgeGraph, VectorMemory, and AttackGraph context (GraphRAG)."""
        # Call the GraphRAG engine to retrieve full context
        context = GraphRAGEngine.retrieve_context(self.db, incident_data)
        # Assure backward compatibility for existing keys
        context["incident"] = incident_data
        return context

    async def _think(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """Perform threat analysis on enriched observation."""
        return await self.threat_analyst.analyze(observation)

    async def _plan(self, analysis: Dict[str, Any], observation: Dict[str, Any]) -> Dict[str, Any]:
        """Draft a mitigation plan and rank actions based on reinforcement memory."""
        plan = await self.mitigation_agent.generate_plan(self.db, analysis, observation)
        
        # Rank actions according to historical defense memory success rates
        actions = plan.get("actions", [])
        attack_pattern = analysis.get("attack_pattern", "Generic")
        ranked_actions = EnhancedDefenseMemory.rank_actions(self.db, attack_pattern, actions)
        
        plan["actions"] = ranked_actions
        return plan

    async def _validate(self, plan: Dict[str, Any], observation: Dict[str, Any], confidence: float) -> Dict[str, Any]:
        """Validate safety thresholds for proposed actions."""
        return await self.validator_agent.validate(plan, observation, confidence)

    async def _execute(self, validation: Dict[str, Any], incident_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute all auto-approved actions."""
        actions_to_execute = validation.get("actions_to_execute", [])
        execution_results = []
        
        for action in actions_to_execute:
            action_type = action.get("type")
            params = action.get("params", {})
            
            logger.info(f"Executing action '{action_type}' autonomously...")
            
            res = {}
            if action_type == "block_ip":
                res = BlockIPTool.execute(
                    self.db,
                    ip_address=params.get("ip_address"),
                    reason=params.get("reason"),
                    duration_hours=params.get("duration_hours", 24)
                )
            elif action_type == "isolate_host":
                res = IsolateHostTool.execute(
                    self.db,
                    hostname=params.get("hostname"),
                    reason=params.get("reason"),
                    notify_admin=params.get("notify_admin", True)
                )
            else:
                res = {"success": False, "error": f"Unknown action type: {action_type}"}
                
            execution_results.append({
                "action": action,
                "result": res
            })
            
        return execution_results

    async def _verify(self, execution_results: List[Dict[str, Any]], incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess whether executed actions successfully mitigated risk, with rollback capabilities (Self-Healing)."""
        if not execution_results:
            return {"status": "no_actions_executed", "effectiveness": 0.0}
            
        verification_details = []
        rollback_details = []
        success_count = 0
        total_count = len(execution_results)
        
        for item in execution_results:
            action = item.get("action", {})
            action_type = action.get("type")
            params = action.get("params", {})
            
            # Verify the action using the Verification Agent
            v_res = VerificationAgent.verify_remediation(self.db, action_type, params)
            verification_details.append(v_res.get("details", ""))
            
            # If verification fails or rollback is recommended, we perform self-healing
            if not v_res.get("success") or v_res.get("rollback_recommended"):
                logger.warning(f"Verification failed or rollback recommended for {action_type}. Performing self-healing rollback...")
                r_res = RollbackManager.execute_rollback(self.db, action_type, params)
                rollback_details.append(r_res.get("details", ""))
            else:
                success_count += 1
                
        effectiveness = float(success_count) / total_count if total_count > 0 else 0.0
        
        status_str = "success"
        if effectiveness < 0.7:
            status_str = "failed"
        if rollback_details:
            status_str = "rolled_back"
            
        return {
            "success_count": success_count,
            "total_count": total_count,
            "effectiveness": effectiveness,
            "status": status_str,
            "verification_details": "; ".join(verification_details),
            "rollback_details": "; ".join(rollback_details) if rollback_details else "No rollback required"
        }

    async def _learn(self, incident_data: Dict[str, Any], execution_results: List[Dict[str, Any]], verification: Dict[str, Any]) -> Dict[str, Any]:
        """Update the vector memory database and defense learning feedback loops."""
        incident_id = incident_data.get("id")
        attack_type = incident_data.get("type", "Generic")
        
        # 1. Store incident description in similarity search vector database
        self.memory_manager.store_incident(incident_data)
        
        # 2. Record action success rates for reinforcement feedback
        learning_records = []
        effectiveness = verification.get("effectiveness", 1.0)
        
        for item in execution_results:
            action = item.get("action", {})
            action_type = action.get("type")
            res_val = item.get("result", {})
            
            result_str = "successful" if res_val.get("success") is True else "failed"
            
            record = self.memory_manager.record_outcome(
                pattern=attack_type,
                action=action_type,
                result=result_str,
                effectiveness=effectiveness,
                incident_id=incident_id
            )
            learning_records.append(record)
            
        return {
            "incident_indexed": True,
            "reinforcement_records": learning_records
        }
