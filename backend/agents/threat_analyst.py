import logging
import json
import re
from typing import Dict, Any
from ai_gateway import AIGateway

logger = logging.getLogger("niravan.agents.threat_analyst")

class ThreatAnalystAgent:
    """
    Threat Analyst Agent analyzes security observations, determines the MITRE ATT&CK technique,
    severity, actor profile, and recommends containment actions.
    """

    async def analyze(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the observation using AI completion or offline rule-based logic.
        """
        system_prompt = (
            "You are a senior threat analyst at NIRAVAN, India's National Cyber Defense OS for Tamil Nadu.\n"
            "Analyze the provided security observation and return a JSON response with:\n"
            "- attack_pattern: the primary ATT&CK technique name\n"
            "- technique_id: MITRE T-code\n"
            "- kill_chain_stage: which stage (Reconnaissance/Weaponization/Delivery/Exploitation/Installation/C2/Actions)\n"
            "- severity: critical/high/medium/low\n"
            "- confidence: 0.0-1.0\n"
            "- root_cause: brief explanation\n"
            "- threat_actor_profile: likely actor type (nation-state/cybercriminal/insider/hacktivist)\n"
            "- recommended_actions: list of action types [\"block_ip\", \"isolate_host\", \"disable_user\", \"rotate_credentials\"]\n"
            "- citizen_impact_estimate: integer estimate of citizens potentially affected\n"
            "- cvss_score: estimated CVSS 3.1 base score\n"
            "Return ONLY valid JSON."
        )
        
        prompt = f"Observation details:\n{json.dumps(observation, indent=2)}"
        
        # Try calling LLM via AI Gateway
        response_text = ""
        try:
            response_text = AIGateway.generate_completion(prompt, system_prompt=system_prompt)
        except Exception as e:
            logger.warning(f"AI Gateway failed to generate completion: {e}. Falling back to local rules.")
            
        if response_text:
            parsed = self._parse_claude_response(response_text)
            if parsed:
                logger.info(f"Successfully analyzed threat via LLM. Severity: {parsed.get('severity')}")
                return parsed
                
        # If AI fails or returns empty string, fall back to local parsing
        logger.info("Using local rule-based analysis fallback.")
        return self._analyze_locally(observation)

    def _parse_claude_response(self, response_text: str) -> Dict[str, Any]:
        """Safely parse JSON from Claude response, extracting from markdown blocks if necessary."""
        try:
            # Try parsing directly
            return json.loads(response_text.strip())
        except Exception:
            # Try to extract JSON using regex if wrapped in code blocks
            try:
                match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
                if match:
                    return json.loads(match.group(1).strip())
                match_any = re.search(r"(\{.*\})", response_text, re.DOTALL)
                if match_any:
                    return json.loads(match_any.group(1).strip())
            except Exception as e:
                logger.error(f"Error parsing JSON from response: {e}")
        return {}

    def _analyze_locally(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """Keyword-based threat analysis fallback using MITRE taxonomy knowledge."""
        obs_text = str(observation).lower()
        
        # Default fallback values
        result = {
            "attack_pattern": "Generic System Compromise",
            "technique_id": "T1499",
            "kill_chain_stage": "Actions on Objectives",
            "severity": "medium",
            "confidence": 0.70,
            "root_cause": "Unusual system behavior observed",
            "threat_actor_profile": "cybercriminal",
            "recommended_actions": ["isolate_host"],
            "citizen_impact_estimate": 1000,
            "cvss_score": 5.0
        }
        
        # Look for specific keywords
        if "nmap" in obs_text or "port scan" in obs_text or "recon" in obs_text:
            result.update({
                "attack_pattern": "Network Service Discovery",
                "technique_id": "T1046",
                "kill_chain_stage": "Reconnaissance",
                "severity": "low",
                "confidence": 0.85,
                "root_cause": "External network port scanning detected",
                "threat_actor_profile": "hacktivist",
                "recommended_actions": ["block_ip"],
                "citizen_impact_estimate": 0,
                "cvss_score": 3.0
            })
        elif "brute force" in obs_text or "failed login" in obs_text or "ssh brute" in obs_text:
            result.update({
                "attack_pattern": "Brute Force",
                "technique_id": "T1110",
                "kill_chain_stage": "Credential Access",
                "severity": "medium",
                "confidence": 0.90,
                "root_cause": "Multiple failed authentication attempts from single source",
                "threat_actor_profile": "cybercriminal",
                "recommended_actions": ["block_ip"],
                "citizen_impact_estimate": 100,
                "cvss_score": 5.5
            })
        elif "mimikatz" in obs_text or "lsass" in obs_text or "credential dump" in obs_text:
            result.update({
                "attack_pattern": "OS Credential Dumping",
                "technique_id": "T1003",
                "kill_chain_stage": "Credential Access",
                "severity": "high",
                "confidence": 0.95,
                "root_cause": "Attempt to dump active system credentials from memory",
                "threat_actor_profile": "nation-state",
                "recommended_actions": ["isolate_host", "rotate_credentials"],
                "citizen_impact_estimate": 10000,
                "cvss_score": 8.0
            })
        elif "ransomware" in obs_text or "encrypt" in obs_text or "lock" in obs_text:
            result.update({
                "attack_pattern": "Data Encrypted for Impact",
                "technique_id": "T1486",
                "kill_chain_stage": "Actions on Objectives",
                "severity": "critical",
                "confidence": 0.98,
                "root_cause": "Active file encryption behavior observed on host",
                "threat_actor_profile": "cybercriminal",
                "recommended_actions": ["isolate_host"],
                "citizen_impact_estimate": 50000,
                "cvss_score": 9.8
            })
        elif "lateral" in obs_text or "psexec" in obs_text or "smb exec" in obs_text:
            result.update({
                "attack_pattern": "SMB/Windows Admin Shares",
                "technique_id": "T1021.002",
                "kill_chain_stage": "Lateral Movement",
                "severity": "high",
                "confidence": 0.85,
                "root_cause": "Unauthorized admin share connections between hosts",
                "threat_actor_profile": "nation-state",
                "recommended_actions": ["isolate_host"],
                "citizen_impact_estimate": 5000,
                "cvss_score": 7.5
            })
            
        return result
