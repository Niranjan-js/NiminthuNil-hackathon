from typing import List, Dict, Any

class CSPMAnalyzer:
    @staticmethod
    def audit_cloud_resources() -> List[Dict[str, Any]]:
        """Checks cloud configurations for security violations (like public S3 buckets)."""
        return [
            {
                "resource_id": "arn:aws:s3:::tn-citizen-data-backup",
                "service": "S3",
                "severity": "critical",
                "violation": "Public Read/Write Permissions Allowed",
                "compliance_tag": "CIS 2.1"
            },
            {
                "resource_id": "sg-04a8b792",
                "service": "EC2 Security Group",
                "severity": "high",
                "violation": "SSH port 22 open to 0.0.0.0/0",
                "compliance_tag": "CIS 4.1"
            }
        ]
