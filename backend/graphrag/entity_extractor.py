import re
from typing import List, Dict, Any

class GraphRAGEntityExtractor:
    @staticmethod
    def extract_entities_from_text(text: str) -> List[Dict[str, Any]]:
        """Parses incident description text to extract assets, users, IPs, and vulnerabilities."""
        entities = []
        
        # Match IPs
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
        for ip in ips:
            entities.append({"type": "IP", "value": ip, "role": "attacker" if ip.startswith("185.") else "victim"})

        # Match assets
        assets = re.findall(r"\b(ast-\d{3}|prod-\w+|dc-\d+)\b", text, re.IGNORECASE)
        for ast in assets:
            entities.append({"type": "Asset", "value": ast.lower(), "role": "target"})

        # Match CVEs
        cves = re.findall(r"\b(CVE-\d{4}-\d{4,7})\b", text, re.IGNORECASE)
        for cve in cves:
            entities.append({"type": "CVE", "value": cve.upper(), "role": "vulnerability"})

        # Match users
        users = re.findall(r"\b([a-zA-Z0-9._%+-]+@tn\.gov\.in)\b", text, re.IGNORECASE)
        for user in users:
            entities.append({"type": "User", "value": user.lower(), "role": "compromised_identity"})

        return entities
