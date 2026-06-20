import logging
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.mitigation_agent")

class MitigationAgent:
    """
    Mitigation Agent that designs response actions, ranks them,
    calculates blast radius (impact), and determines human approval requirements.
    """

    async def generate_plan(self, db, analysis: Dict[str, Any], observation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a structured response plan containing prioritized mitigation actions.
        """
        try:
            # Retrieve similar cases from VectorMemory and extract historically successful playbooks
            similar_incidents = observation.get("similar_past_incidents", [])
            historical_actions = []
            if similar_incidents:
                try:
                    from main import DefenseMemoryModel
                    similar_ids = [item.get("incident_id") for item in similar_incidents if item.get("incident_id")]
                    if similar_ids:
                        past_memories = db.query(DefenseMemoryModel).filter(
                            DefenseMemoryModel.incident_id.in_(similar_ids)
                        ).all()
                        # Sort/prioritize successful historical actions
                        for pm in past_memories:
                            if pm.action and pm.action not in historical_actions:
                                if pm.result == "successful" or (hasattr(pm, "effectiveness_score") and pm.effectiveness_score and pm.effectiveness_score >= 0.7):
                                    historical_actions.append(pm.action)
                except Exception as e:
                    logger.warning(f"Failed to query historical playbooks from similar incidents: {e}")

            # Merge recommended actions with historical actions, putting historical successes first
            recommended_types = []
            for ha in historical_actions:
                if ha not in recommended_types:
                    recommended_types.append(ha)
            for ra in analysis.get("recommended_actions", []):
                if ra not in recommended_types:
                    recommended_types.append(ra)
            if not recommended_types:
                recommended_types = ["isolate_host"]
            
            actions = []
            priority = 1
            
            # Extract possible IP and hostname from observation
            ip_address = observation.get("ip_address") or observation.get("ip") or observation.get("source_ip")
            hostname = observation.get("host") or observation.get("hostname") or observation.get("target_host")
            
            # If not direct, look in telemetry details
            if not ip_address and "payload" in observation:
                # Try to parse or search payload for IP
                payload_str = str(observation["payload"])
                import re
                ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', payload_str)
                if ip_match:
                    ip_address = ip_match.group(0)
            
            for action_type in recommended_types:
                action_item = None
                
                if action_type == "block_ip" and ip_address:
                    action_item = {
                        "type": "block_ip",
                        "params": {
                            "ip_address": ip_address,
                            "reason": f"Automated block for technique {analysis.get('technique_id')} ({analysis.get('attack_pattern')})",
                            "duration_hours": 24
                        },
                        "reason": f"Block traffic from attacker source IP: {ip_address}",
                        "priority": priority,
                        "estimated_success_rate": 0.94
                    }
                elif action_type == "isolate_host" and hostname:
                    action_item = {
                        "type": "isolate_host",
                        "params": {
                            "hostname": hostname,
                            "reason": f"Contain lateral movement / active compromise of {hostname}",
                            "notify_admin": True
                        },
                        "reason": f"Isolate compromised host {hostname} from the network",
                        "priority": priority,
                        "estimated_success_rate": 0.97
                    }
                elif action_type == "rotate_credentials" or action_type == "disable_user":
                    user = observation.get("user") or observation.get("username")
                    if user:
                        action_item = {
                            "type": "disable_user",
                            "params": {
                                "username": user,
                                "reason": f"Compromised account activity detected: {analysis.get('root_cause')}"
                            },
                            "reason": f"Disable or rotate credentials for user: {user}",
                            "priority": priority,
                            "estimated_success_rate": 0.90
                        }
                        
                if action_item:
                    # Estimate blast radius (impact of taking this action)
                    blast = self._estimate_blast_radius(db, action_item, observation)
                    action_item["blast_radius"] = blast
                    actions.append(action_item)
                    priority += 1

            # Determine if human approval is required
            # Require approval if confidence is low, severity is critical, or blast radius is high
            confidence = analysis.get("confidence", 0.0)
            severity = analysis.get("severity", "medium")
            
            has_high_blast = any(a.get("blast_radius", 0) > 3 for a in actions)
            
            human_approval_required = (
                confidence < 0.85 or 
                severity == "critical" or 
                has_high_blast
            )
            
            reasoning = f"Plan generated based on threat analysis (Severity: {severity}, Confidence: {confidence:.2f})."
            if human_approval_required:
                reasoning += " Human approval is required due to "
                reasons = []
                if confidence < 0.85:
                    reasons.append(f"low analyst confidence ({confidence:.2f})")
                if severity == "critical":
                    reasons.append("critical incident severity")
                if has_high_blast:
                    reasons.append("high estimated containment blast radius (>3 assets)")
                reasoning += ", ".join(reasons) + "."
            else:
                reasoning += " Auto-execution recommended."

            return {
                "actions": actions,
                "reasoning": reasoning,
                "estimated_containment_time": "Less than 5 minutes" if not human_approval_required else "Pending approval",
                "human_approval_required": human_approval_required
            }
        except Exception as e:
            logger.error(f"Error generating mitigation plan: {e}")
            return {
                "actions": [],
                "reasoning": f"Failed to generate mitigation plan: {e}",
                "estimated_containment_time": "Unknown",
                "human_approval_required": True
            }

    def _estimate_blast_radius(self, db, action: Dict[str, Any], observation: Dict[str, Any]) -> int:
        """
        Estimate the blast radius (number of affected nodes) if we take this response action.
        """
        try:
            from graphs.attack_graph import AttackGraph
            
            action_type = action.get("type")
            params = action.get("params", {})
            
            if action_type == "isolate_host":
                hostname = params.get("hostname")
                if hostname:
                    # Query the attack graph to calculate real BFS blast radius
                    graph = AttackGraph.build_from_db(db)
                    
                    # Find asset node id
                    node_id = None
                    for node in graph.get("nodes", []):
                        if node["name"] == hostname or node["id"] == hostname:
                            node_id = node["id"]
                            break
                            
                    if node_id:
                        blast_nodes = AttackGraph.calculate_blast_radius(graph, node_id)
                        # Filter to count asset or service nodes only (exclude IOCs or internet)
                        assets_affected = sum(
                            1 for n_id in blast_nodes 
                            for n in graph.get("nodes", []) 
                            if n["id"] == n_id and n["type"] in ["asset", "service"]
                        )
                        logger.info(f"Blast radius calculation for {hostname}: {assets_affected} assets affected.")
                        return assets_affected
                        
            elif action_type == "block_ip":
                # Blocking an external IP usually has 0 local blast radius, except if the IP belongs to a proxy/VPN used by many
                return 0
                
            return 1  # Default conservative estimate
        except Exception as e:
            logger.warning(f"Failed to calculate blast radius using graph: {e}. Using fallback.")
            return 1
