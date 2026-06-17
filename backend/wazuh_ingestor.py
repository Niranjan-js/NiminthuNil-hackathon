import datetime
from typing import Dict, Any, Optional

class WazuhIngestor:
    @staticmethod
    def parse_log(source_type: str, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parses and normalizes logs from endpoints, audit logs, syslogs, and firewalls.
        Returns a standardized event dictionary:
        {
            "timestamp": "ISO-8601 String",
            "source_type": str,
            "host": str,
            "user": str or None,
            "ip_address": str or None,
            "event_name": str,
            "description": str,
            "severity": "low" | "medium" | "high" | "critical",
            "mitre": list of str,
            "technique": str,
            "raw_payload": dict
        }
        """
        # Default fallback structure
        now_str = datetime.datetime.utcnow().isoformat() + "Z"
        normalized = {
            "timestamp": log_data.get("timestamp") or now_str,
            "source_type": source_type,
            "host": log_data.get("host") or "unknown-host",
            "user": log_data.get("user") or log_data.get("username"),
            "ip_address": log_data.get("ip_address") or log_data.get("src_ip") or log_data.get("ip"),
            "event_name": "Generic Telemetry Event",
            "description": "Raw telemetry event ingested.",
            "severity": "low",
            "mitre": [],
            "technique": "T1000", # general technique code
            "raw_payload": log_data
        }

        # 1. Windows Sysmon Normalization
        if source_type in ["windows_sysmon", "sysmon"]:
            event_id = int(log_data.get("EventID") or log_data.get("event_id") or 0)
            if event_id == 0 and ("CommandLine" in log_data or "cmd" in log_data):
                event_id = 1
            normalized["host"] = log_data.get("Computer") or log_data.get("host") or "WIN-ENDPOINT"
            
            if event_id == 1:
                # Process Creation
                cmd = log_data.get("CommandLine") or log_data.get("cmd", "")
                image = log_data.get("Image", "")
                parent = log_data.get("ParentCommandLine", "")
                normalized["event_name"] = "Process Created (Sysmon Event ID 1)"
                normalized["description"] = f"Process {image} created with command line: {cmd}"
                normalized["user"] = log_data.get("User") or log_data.get("user")
                
                # Check for suspect commands
                cmd_lower = cmd.lower()
                if "vssadmin" in cmd_lower and "delete" in cmd_lower and "shadows" in cmd_lower:
                    normalized["event_name"] = "Ransomware Shadow Copy Deletion (SIG-002)"
                    normalized["severity"] = "critical"
                    normalized["mitre"] = ["T1486"]
                    normalized["technique"] = "Data Encrypted for Impact"
                elif "mimikatz" in cmd_lower or "sekurlsa" in cmd_lower or "lsass" in cmd_lower:
                    normalized["event_name"] = "PowerShell Credential Dump (SIG-004)"
                    normalized["severity"] = "critical"
                    normalized["mitre"] = ["T1003"]
                    normalized["technique"] = "OS Credential Dumping"
                elif "nmap" in cmd_lower:
                    normalized["event_name"] = "Advanced Network Scan Detected (SIG-005)"
                    normalized["severity"] = "high"
                    normalized["mitre"] = ["T1046"]
                    normalized["technique"] = "Network Service Discovery"
                elif "msfconsole" in cmd_lower or "msfvenom" in cmd_lower or "meterpreter" in cmd_lower:
                    normalized["event_name"] = "Metasploit Exploitation Framework Detected (SIG-006)"
                    normalized["severity"] = "critical"
                    normalized["mitre"] = ["T1210", "T1059"]
                    normalized["technique"] = "Exploitation of Remote Services"
                elif "sqlmap" in cmd_lower:
                    normalized["event_name"] = "SQLmap Automated SQL Injection Attack Detected (SIG-007)"
                    normalized["severity"] = "critical"
                    normalized["mitre"] = ["T1190"]
                    normalized["technique"] = "Exploit Public-Facing Application: SQL Injection"
                elif "hydra" in cmd_lower or "john" in cmd_lower or "hashcat" in cmd_lower:
                    normalized["event_name"] = "Automated Credential Brute-Force/Crack Tool Detected (SIG-008)"
                    normalized["severity"] = "high"
                    normalized["mitre"] = ["T1110.001", "T1110.002"]
                    normalized["technique"] = "Brute Force: Password Cracking"
                elif any(p in cmd_lower for p in ["alien_program", "reverse_shell", "nc -e", "netcat", "/tmp/malware"]):
                    normalized["event_name"] = "Alien Program/RAT Injection Detected (SIG-010)"
                    normalized["severity"] = "critical"
                    normalized["mitre"] = ["T1105"]
                    normalized["technique"] = "Ingress Tool Transfer"
                    normalized["description"] = "CRITICAL — CAMERA CAPTURE TRIGGERED: Alien program/RAT injection detected on local host."
                elif "powershell" in cmd_lower or "pwsh" in cmd_lower:
                    normalized["severity"] = "medium"
                    normalized["mitre"] = ["T1059.001"]
                    normalized["technique"] = "PowerShell Execution"
                else:
                    normalized["severity"] = "low"
                    normalized["mitre"] = ["T1059"]
                    normalized["technique"] = "Command and Scripting Interpreter"
                    
            elif event_id == 3:
                # Network Connection
                dest_ip = log_data.get("DestinationIp") or log_data.get("dest_ip")
                dest_port = log_data.get("DestinationPort") or log_data.get("dest_port")
                normalized["event_name"] = "Network Connection Created (Sysmon Event ID 3)"
                normalized["description"] = f"Network connection established to {dest_ip}:{dest_port}"
                normalized["ip_address"] = dest_ip
                normalized["severity"] = "low"
                normalized["mitre"] = ["T1011"]
                normalized["technique"] = "Exfiltration Over Alternative Protocol"
                
            elif event_id == 7:
                # DLL Load
                dll = log_data.get("ImageLoaded") or log_data.get("dll", "")
                normalized["event_name"] = "DLL Image Loaded (Sysmon Event ID 7)"
                normalized["description"] = f"Module loaded: {dll}"
                normalized["severity"] = "low"
                normalized["mitre"] = ["T1574.002"]
                normalized["technique"] = "DLL Side-Loading"
                
            elif event_id == 11:
                # File Create
                filename = log_data.get("TargetFilename") or log_data.get("file_path", "")
                normalized["event_name"] = "File Created (Sysmon Event ID 11)"
                normalized["description"] = f"File created on disk: {filename}"
                normalized["severity"] = "low"
                if filename.endswith(".exe") or filename.endswith(".dll") or filename.endswith(".sh") or filename.endswith(".bat"):
                    normalized["severity"] = "medium"
                    normalized["mitre"] = ["T1105"]
                    normalized["technique"] = "Ingress Tool Transfer"
                elif ".txt.locked" in filename or ".crypt" in filename or "README" in filename:
                    normalized["severity"] = "critical"
                    normalized["mitre"] = ["T1486"]
                    normalized["technique"] = "Data Encrypted for Impact"
                    
            elif event_id == 22:
                # DNS Query
                query = log_data.get("QueryName") or log_data.get("query", "")
                normalized["event_name"] = "DNS Query Resolved (Sysmon Event ID 22)"
                normalized["description"] = f"DNS resolution query for domain: {query}"
                normalized["severity"] = "low"
                normalized["mitre"] = ["T1071.004"]
                normalized["technique"] = "Application Layer Protocol: DNS"

        # 2. Windows Event Logs Normalization
        elif source_type in ["windows_event", "windows_log"]:
            event_id = int(log_data.get("EventID") or log_data.get("event_id") or 0)
            normalized["host"] = log_data.get("Computer") or log_data.get("host") or "WIN-ENDPOINT"
            
            if event_id == 4624:
                normalized["event_name"] = "Successful Logon (EventID 4624)"
                normalized["user"] = log_data.get("TargetUserName") or log_data.get("user")
                normalized["ip_address"] = log_data.get("IpAddress") or log_data.get("src_ip")
                normalized["description"] = f"Successful login for user {normalized['user']} from IP {normalized['ip_address']}"
                normalized["severity"] = "low"
                normalized["mitre"] = ["T1078"]
                normalized["technique"] = "Valid Accounts"
            elif event_id == 4625:
                normalized["event_name"] = "Failed Logon Attempt (EventID 4625)"
                normalized["user"] = log_data.get("TargetUserName") or log_data.get("user")
                normalized["ip_address"] = log_data.get("IpAddress") or log_data.get("src_ip")
                normalized["description"] = f"Failed login attempt for user {normalized['user']} from IP {normalized['ip_address']}"
                normalized["severity"] = "medium"
                normalized["mitre"] = ["T1110"]
                normalized["technique"] = "Brute Force"
            elif event_id == 7045:
                service = log_data.get("ServiceName") or log_data.get("service")
                path = log_data.get("ImagePath") or log_data.get("path")
                normalized["event_name"] = "New Service Installed (EventID 7045)"
                normalized["description"] = f"A new service '{service}' was installed with binary path: {path}"
                normalized["severity"] = "high"
                normalized["mitre"] = ["T1543.003"]
                normalized["technique"] = "Create or Modify System Process: Windows Service"

        # 3. Linux Auditd Normalization
        elif source_type in ["linux_auditd", "auditd"]:
            exe = log_data.get("exe") or log_data.get("comm") or "unknown"
            syscall = log_data.get("syscall") or "sys"
            normalized["event_name"] = f"Linux Syscall Triggered ({syscall})"
            normalized["user"] = log_data.get("uid") or log_data.get("user")
            normalized["description"] = f"Linux auditd logged execution of '{exe}' (syscall: {syscall})"
            normalized["severity"] = "low"
            normalized["mitre"] = ["T1059.004"]
            normalized["technique"] = "Unix Shell Execution"
            
            # Identify suspect tools or privilege escalation command execution
            exe_lower = exe.lower()
            if "nmap" in exe_lower:
                normalized["event_name"] = "Advanced Network Scan Detected (SIG-005)"
                normalized["severity"] = "high"
                normalized["mitre"] = ["T1046"]
                normalized["technique"] = "Network Service Discovery"
            elif "msfconsole" in exe_lower or "msfvenom" in exe_lower or "meterpreter" in exe_lower:
                normalized["event_name"] = "Metasploit Exploitation Framework Detected (SIG-006)"
                normalized["severity"] = "critical"
                normalized["mitre"] = ["T1210", "T1059"]
                normalized["technique"] = "Exploitation of Remote Services"
            elif "sqlmap" in exe_lower:
                normalized["event_name"] = "SQLmap Automated SQL Injection Attack Detected (SIG-007)"
                normalized["severity"] = "critical"
                normalized["mitre"] = ["T1190"]
                normalized["technique"] = "Exploit Public-Facing Application: SQL Injection"
            elif "hydra" in exe_lower or "john" in exe_lower or "hashcat" in exe_lower:
                normalized["event_name"] = "Automated Credential Brute-Force/Crack Tool Detected (SIG-008)"
                normalized["severity"] = "high"
                normalized["mitre"] = ["T1110.001", "T1110.002"]
                normalized["technique"] = "Brute Force: Password Cracking"
            elif "/bin/chmod" in exe or "/bin/chown" in exe or "sudo" in exe:
                normalized["severity"] = "medium"
                normalized["mitre"] = ["T1548.001"]
                normalized["technique"] = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"

        # 4. Linux Syslog & Authentication Events
        elif source_type in ["linux_syslog", "auth_event", "syslog"]:
            message = log_data.get("message") or log_data.get("log") or ""
            normalized["description"] = message
            normalized["severity"] = "low"
            normalized["mitre"] = ["T1110"]
            normalized["technique"] = "Brute Force"
            
            if "Failed password" in message or "Authentication failure" in message or "invalid user" in message:
                normalized["event_name"] = "Authentication Failure Logged"
                normalized["severity"] = "medium"
                normalized["mitre"] = ["T1110.001"]
                normalized["technique"] = "Brute Force: Password Brute Forcing"
            elif "Accepted password" in message or "session opened" in message:
                normalized["event_name"] = "Authentication Successful Logged"
                normalized["severity"] = "low"
                normalized["mitre"] = ["T1078.003"]
                normalized["technique"] = "Valid Accounts: Local Accounts"

        # 5. Firewall Logs Normalization
        elif source_type == "firewall":
            action = log_data.get("action") or log_data.get("status") or "ALLOW"
            src_ip = log_data.get("src_ip") or log_data.get("source_ip")
            dest_ip = log_data.get("dest_ip") or log_data.get("destination_ip")
            port = log_data.get("dest_port") or log_data.get("port")
            normalized["event_name"] = f"Firewall Connection {action}"
            normalized["description"] = f"Firewall packet connection {action} from {src_ip} to {dest_ip}:{port}"
            normalized["ip_address"] = src_ip
            normalized["mitre"] = ["T1046"]
            normalized["technique"] = "Network Service Discovery"
            
            if action.upper() == "DENY" or action.upper() == "BLOCK":
                normalized["severity"] = "medium"
            else:
                normalized["severity"] = "low"

        # 6. DNS Logs Normalization
        elif source_type == "dns":
            query = log_data.get("query") or log_data.get("domain") or ""
            client = log_data.get("client_ip") or log_data.get("client")
            normalized["event_name"] = "DNS Query Logged"
            normalized["description"] = f"DNS query request from client {client} for domain: {query}"
            normalized["ip_address"] = client
            normalized["severity"] = "low"
            normalized["mitre"] = ["T1071.004"]
            normalized["technique"] = "Application Layer Protocol: DNS"

        # 7. Proxy Logs Normalization
        elif source_type == "proxy":
            uri = log_data.get("uri") or log_data.get("url") or ""
            status = log_data.get("status_code") or log_data.get("status") or 200
            method = log_data.get("method") or "GET"
            normalized["event_name"] = "Web Proxy Request Logged"
            normalized["description"] = f"Proxy request: {method} {uri} returned status: {status}"
            normalized["severity"] = "low"
            normalized["mitre"] = ["T1071.001"]
            normalized["technique"] = "Application Layer Protocol: Web Protocols"
            
            uri_lower = uri.lower()
            user_agent = (log_data.get("User-Agent") or log_data.get("user_agent") or "").lower()
            
            if "sqlmap" in user_agent or "sqlmap" in uri_lower:
                normalized["event_name"] = "SQLmap Automated SQL Injection Attack Detected (SIG-007)"
                normalized["severity"] = "critical"
                normalized["mitre"] = ["T1190"]
                normalized["technique"] = "Exploit Public-Facing Application: SQL Injection"
                normalized["description"] = f"CRITICAL: SQLmap automated attack tool detected in request: {method} {uri}"
            elif any(sqli in uri_lower for sqli in ["union select", "select database()", "select version()", "information_schema", "pg_sleep", "benchmark("]):
                normalized["event_name"] = "SQL Injection Attempt Detected (SIG-009)"
                normalized["severity"] = "critical"
                normalized["mitre"] = ["T1190"]
                normalized["technique"] = "Exploit Public-Facing Application: SQL Injection"
                normalized["description"] = f"CRITICAL: SQL injection payloads detected in request URI: {uri}"
            elif any(p in uri_lower for p in ["/admin", "/wp-admin", "/phpmyadmin", "/etc/passwd"]):
                normalized["severity"] = "high"
                normalized["mitre"] = ["T1046"]
                normalized["technique"] = "Network Service Discovery"

        return normalized
