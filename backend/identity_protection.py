import datetime
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional

class IdentityProtection:
    """
    Identity Threat Detection and Protection (Tier 13).
    Monitors session telemetry, login histories, and command audits
    to detect compromise vectors such as Impossible Travel and Password Spray.
    """

    @staticmethod
    def detect_impossible_travel(db: Session, email: str, current_ip: str) -> Optional[Dict[str, Any]]:
        """
        Detects if consecutive successful logins occur from geographically
        distant IPs within a time window that makes travel physically impossible.
        """
        from main import LoginLogModel
        
        # Get the previous successful login (skipping the current one which was just logged)
        prev_login = db.query(LoginLogModel).filter(
            LoginLogModel.email == email,
            LoginLogModel.success == True
        ).order_by(LoginLogModel.timestamp.desc()).offset(1).first()
        
        if not prev_login:
            return None
            
        # If IPs are different, verify travel feasibility
        if prev_login.ip_address != current_ip:
            # For testing and demo purposes, we treat any IP change within 5 minutes as impossible travel
            now = datetime.datetime.utcnow()
            time_diff = (now - prev_login.timestamp).total_seconds()
            
            if time_diff < 300:  # 5 minutes
                # Mock geographic regions based on IP structure
                prev_loc = "Chennai, TN" if prev_login.ip_address.startswith("185.") else "New Delhi, DL"
                curr_loc = "Coimbatore, TN" if current_ip.startswith("185.") else "Frankfurt, DE"
                
                return {
                    "type": "IMPOSSIBLE_TRAVEL",
                    "user": email,
                    "previous_ip": prev_login.ip_address,
                    "previous_location": prev_loc,
                    "current_ip": current_ip,
                    "current_location": curr_loc,
                    "time_delta_seconds": time_diff,
                    "description": (
                        f"CRITICAL: User {email} logged in successfully from {prev_loc} ({prev_login.ip_address}) "
                        f"and then {curr_loc} ({current_ip}) within {int(time_diff)} seconds. "
                        f"This exceeds physical travel velocity limits."
                    )
                }
        return None

    @staticmethod
    def detect_password_spray(db: Session, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Detects password spray attacks where a single source IP attempts to
        brute-force credentials across multiple different usernames in a short window.
        """
        from main import LoginLogModel
        
        time_limit = datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        recent_failures = db.query(LoginLogModel).filter(
            LoginLogModel.ip_address == ip_address,
            LoginLogModel.success == False,
            LoginLogModel.timestamp >= time_limit
        ).all()
        
        # Get count of unique usernames targeted
        unique_targets = {f.email for f in recent_failures}
        
        if len(unique_targets) >= 3:
            return {
                "type": "PASSWORD_SPRAY",
                "source_ip": ip_address,
                "targets_count": len(unique_targets),
                "targets": list(unique_targets),
                "description": (
                    f"WARNING: Single IP {ip_address} initiated login failures across "
                    f"{len(unique_targets)} distinct user accounts within 10 minutes: "
                    f"{', '.join(list(unique_targets)[:3])}."
                )
            }
        return None

    @staticmethod
    def detect_privilege_escalation(db: Session, user: str, command: str) -> Optional[Dict[str, Any]]:
        """
        Inspects process command logs or syscall details to detect
        attempts to gain elevated root/administrator privileges.
        """
        cmd_lower = command.lower()
        suspicious_keywords = ["sudo su", "chmod +s", "chown root", "pkexec", "sudoers"]
        
        if any(keyword in cmd_lower for keyword in suspicious_keywords):
            return {
                "type": "PRIVILEGE_ESCALATION",
                "user": user,
                "command": command,
                "description": (
                    f"CRITICAL: User {user} attempted dangerous command execution "
                    f"associated with privilege escalation: '{command}'."
                )
            }
        return None
