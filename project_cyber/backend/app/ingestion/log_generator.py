"""
Contexta Backend - Fake SIEM Log Generator

This module generates realistic security logs for testing and demonstration.
"""

import random
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from uuid import UUID
import structlog

from app.models.log import LogCategory, LogSeverity

logger = structlog.get_logger()


class FakeLogGenerator:
    """
    Fake SIEM Log Generator for realistic security events.
    
    Generates the following log types:
    - Login failures
    - Port scans
    - Malware alerts
    - Privilege escalation
    - Data exfiltration attempts
    - Brute force attacks
    - Anomaly detection
    """
    
    # Sample IP ranges for different threat actors
    MALICIOUS_IPS = [
        "185.220.101.",  # Tor exit nodes
        "45.33.32.",     # Generic VPS
        "104.244.72.",   # Known bad actors
        "23.129.64.",    # Suspicious hosting
        "192.42.116.",   # More Tor nodes
    ]
    
    INTERNAL_IPS = [
        "10.0.1.",
        "10.0.2.",
        "10.0.3.",
        "10.0.4.",
        "10.0.5.",
        "192.168.1.",
    ]
    
    # Common usernames for attacks
    USERNAMES = [
        "admin", "administrator", "root", "user", "test", "guest",
        "support", "service", "backup", "oracle", "mysql", "postgres",
        "ftp", "www-data", "nginx", "apache", "jenkins", "git"
    ]
    
    # Legitimate internal usernames
    INTERNAL_USERS = [
        "john.smith", "jane.doe", "mike.wilson", "sarah.jones",
        "admin.support", "it.helpdesk", "security.team", "dev.ops"
    ]
    
    # Common malware names
    MALWARE_NAMES = [
        "Emotet", "TrickBot", "Ryuk", "Conti", "LockBit",
        "Cobalt Strike", "Mimikatz", "BloodHound", "Metasploit",
        "PowerSploit", "SharpHound", "Rubeus", "CrackMapExec"
    ]
    
    # Common ports for scanning
    SCAN_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200
    ]
    
    # Log sources
    LOG_SOURCES = [
        "firewall", "ids", "edr", "siem", "antivirus", "proxy",
        "windows_security", "linux_audit", "cloudtrail", "waf"
    ]
    
    def __init__(self, seed: int = None):
        """
        Initialize log generator.
        
        Args:
            seed: Random seed for reproducibility
        """
        if seed:
            random.seed(seed)
    
    def generate_login_failure(
        self,
        asset_id: UUID = None,
        target_ip: str = None
    ) -> Dict[str, Any]:
        """
        Generate a login failure event.
        
        Args:
            asset_id: Target asset UUID
            target_ip: Target IP address
            
        Returns:
            Security log dictionary
        """
        source_ip = self._random_ip(malicious=random.random() > 0.3)
        dest_ip = target_ip or self._random_ip(internal=True)
        username = random.choice(self.USERNAMES)
        
        # Determine severity based on patterns
        severity = LogSeverity.LOW
        if username in ["root", "admin", "administrator"]:
            severity = LogSeverity.MEDIUM
        if source_ip.startswith(tuple(self.MALICIOUS_IPS)):
            severity = LogSeverity.HIGH
        
        return {
            "source": random.choice(["windows_security", "linux_audit", "siem"]),
            "category": LogCategory.LOGIN_FAILURE,
            "severity": severity,
            "message": f"Failed login attempt for user '{username}' from {source_ip}",
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": random.choice([22, 3389, 445, 5900]),
            "username": username,
            "asset_id": asset_id,
            "raw_log": {
                "event_type": "authentication_failure",
                "username": username,
                "source_ip": source_ip,
                "auth_method": random.choice(["password", "kerberos", "ntlm"]),
                "failure_reason": random.choice([
                    "invalid_password",
                    "account_locked",
                    "expired_password",
                    "unknown_user"
                ])
            },
            "indicators": {
                "ips": [source_ip]
            }
        }
    
    def generate_port_scan(
        self,
        asset_id: UUID = None,
        target_ip: str = None
    ) -> Dict[str, Any]:
        """
        Generate a port scan detection event.
        
        Args:
            asset_id: Target asset UUID
            target_ip: Target IP address
            
        Returns:
            Security log dictionary
        """
        source_ip = self._random_ip(malicious=True)
        dest_ip = target_ip or self._random_ip(internal=True)
        scanned_ports = random.sample(self.SCAN_PORTS, k=random.randint(5, 15))
        
        scan_type = random.choice(["syn", "connect", "fin", "xmas", "null", "udp"])
        
        return {
            "source": random.choice(["firewall", "ids", "siem"]),
            "category": LogCategory.PORT_SCAN,
            "severity": LogSeverity.MEDIUM,
            "message": f"{scan_type.upper()} scan detected from {source_ip} targeting {len(scanned_ports)} ports",
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": scanned_ports[0],
            "username": None,
            "asset_id": asset_id,
            "raw_log": {
                "event_type": "port_scan",
                "scan_type": scan_type,
                "ports_scanned": scanned_ports,
                "packets_sent": random.randint(100, 10000),
                "duration_seconds": random.randint(5, 300)
            },
            "indicators": {
                "ips": [source_ip]
            }
        }
    
    def generate_malware_alert(
        self,
        asset_id: UUID = None,
        target_ip: str = None
    ) -> Dict[str, Any]:
        """
        Generate a malware detection alert.
        
        Args:
            asset_id: Target asset UUID
            target_ip: Target IP address
            
        Returns:
            Security log dictionary
        """
        dest_ip = target_ip or self._random_ip(internal=True)
        malware = random.choice(self.MALWARE_NAMES)
        user = random.choice(self.INTERNAL_USERS)
        
        # Generate fake hash
        file_hash = uuid.uuid4().hex + uuid.uuid4().hex[:32]
        
        detection_type = random.choice([
            "signature", "heuristic", "behavioral", "sandbox"
        ])
        
        severity = LogSeverity.HIGH
        if malware in ["Ryuk", "Conti", "LockBit", "Emotet"]:
            severity = LogSeverity.CRITICAL
        
        return {
            "source": random.choice(["edr", "antivirus", "siem"]),
            "category": LogCategory.MALWARE_ALERT,
            "severity": severity,
            "message": f"{malware} detected on {dest_ip} ({detection_type} detection)",
            "source_ip": None,
            "destination_ip": dest_ip,
            "source_port": None,
            "destination_port": None,
            "username": user,
            "asset_id": asset_id,
            "raw_log": {
                "event_type": "malware_detected",
                "malware_name": malware,
                "malware_family": malware.lower(),
                "detection_method": detection_type,
                "file_path": f"C:\\Users\\{user}\\Downloads\\invoice_{random.randint(1000,9999)}.exe",
                "file_hash_sha256": file_hash,
                "action_taken": random.choice(["quarantined", "blocked", "cleaned"]),
                "process_name": f"{malware.lower()}.exe"
            },
            "indicators": {
                "hashes": [file_hash],
                "file_names": [f"invoice_{random.randint(1000,9999)}.exe"]
            }
        }
    
    def generate_privilege_escalation(
        self,
        asset_id: UUID = None,
        target_ip: str = None
    ) -> Dict[str, Any]:
        """
        Generate a privilege escalation attempt event.
        
        Args:
            asset_id: Target asset UUID
            target_ip: Target IP address
            
        Returns:
            Security log dictionary
        """
        dest_ip = target_ip or self._random_ip(internal=True)
        source_user = random.choice(self.INTERNAL_USERS)
        target_user = random.choice(["root", "SYSTEM", "Administrator", "Domain Admin"])
        
        technique = random.choice([
            "sudo_abuse", "setuid_binary", "kernel_exploit", "token_manipulation",
            "dll_hijacking", "service_creation", "scheduled_task", "pass_the_hash"
        ])
        
        return {
            "source": random.choice(["edr", "linux_audit", "windows_security", "siem"]),
            "category": LogCategory.PRIVILEGE_ESCALATION,
            "severity": LogSeverity.CRITICAL,
            "message": f"Privilege escalation attempt detected: {source_user} -> {target_user} via {technique}",
            "source_ip": dest_ip,
            "destination_ip": dest_ip,
            "source_port": None,
            "destination_port": None,
            "username": source_user,
            "asset_id": asset_id,
            "raw_log": {
                "event_type": "privilege_escalation",
                "source_user": source_user,
                "target_user": target_user,
                "technique": technique,
                "process_name": random.choice([
                    "powershell.exe", "cmd.exe", "sudo", "su", "mimikatz.exe"
                ]),
                "command_line": self._generate_suspicious_command(technique),
                "success": random.choice([True, False])
            },
            "indicators": {}
        }
    
    def generate_data_exfiltration(
        self,
        asset_id: UUID = None,
        target_ip: str = None
    ) -> Dict[str, Any]:
        """
        Generate a data exfiltration attempt event.
        
        Args:
            asset_id: Target asset UUID
            target_ip: Target IP address
            
        Returns:
            Security log dictionary
        """
        source_ip = target_ip or self._random_ip(internal=True)
        dest_ip = self._random_ip(malicious=True)
        user = random.choice(self.INTERNAL_USERS)
        
        bytes_transferred = random.randint(1000000, 1000000000)  # 1MB to 1GB
        
        protocol = random.choice(["https", "dns", "ftp", "smb", "custom"])
        
        return {
            "source": random.choice(["proxy", "firewall", "dlp", "siem"]),
            "category": LogCategory.DATA_EXFILTRATION,
            "severity": LogSeverity.CRITICAL,
            "message": f"Potential data exfiltration: {self._format_bytes(bytes_transferred)} sent to {dest_ip} via {protocol}",
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": self._get_port_for_protocol(protocol),
            "username": user,
            "asset_id": asset_id,
            "raw_log": {
                "event_type": "data_exfiltration",
                "protocol": protocol,
                "bytes_transferred": bytes_transferred,
                "destination_domain": f"suspicious-{random.randint(100,999)}.com",
                "file_types": random.sample(
                    ["docx", "xlsx", "pdf", "zip", "sql", "csv", "json"],
                    k=random.randint(1, 4)
                ),
                "duration_seconds": random.randint(60, 3600)
            },
            "indicators": {
                "ips": [dest_ip],
                "domains": [f"suspicious-{random.randint(100,999)}.com"]
            }
        }
    
    def generate_brute_force(
        self,
        asset_id: UUID = None,
        target_ip: str = None
    ) -> Dict[str, Any]:
        """
        Generate a brute force attack event.
        
        Args:
            asset_id: Target asset UUID
            target_ip: Target IP address
            
        Returns:
            Security log dictionary
        """
        source_ip = self._random_ip(malicious=True)
        dest_ip = target_ip or self._random_ip(internal=True)
        
        attempt_count = random.randint(50, 5000)
        unique_users = random.randint(1, min(20, attempt_count))
        
        target_service = random.choice(["ssh", "rdp", "smb", "ftp", "web_login"])
        
        return {
            "source": random.choice(["firewall", "ids", "siem"]),
            "category": LogCategory.BRUTE_FORCE,
            "severity": LogSeverity.HIGH,
            "message": f"Brute force attack on {target_service}: {attempt_count} attempts from {source_ip}",
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": self._get_port_for_service(target_service),
            "username": None,
            "asset_id": asset_id,
            "raw_log": {
                "event_type": "brute_force",
                "target_service": target_service,
                "attempt_count": attempt_count,
                "unique_usernames": unique_users,
                "successful_attempts": random.randint(0, 2),
                "time_window_minutes": random.randint(5, 60),
                "usernames_tried": random.sample(self.USERNAMES, k=min(5, unique_users))
            },
            "indicators": {
                "ips": [source_ip]
            }
        }
    
    def generate_anomaly(
        self,
        asset_id: UUID = None,
        target_ip: str = None
    ) -> Dict[str, Any]:
        """
        Generate an anomaly detection event.
        
        Args:
            asset_id: Target asset UUID
            target_ip: Target IP address
            
        Returns:
            Security log dictionary
        """
        dest_ip = target_ip or self._random_ip(internal=True)
        user = random.choice(self.INTERNAL_USERS)
        
        anomaly_type = random.choice([
            "unusual_login_time", "geographic_anomaly", "data_access_spike",
            "process_anomaly", "network_traffic_anomaly", "user_behavior_anomaly"
        ])
        
        confidence = random.randint(70, 99)
        
        return {
            "source": random.choice(["ueba", "ml_engine", "siem"]),
            "category": LogCategory.ANOMALY,
            "severity": LogSeverity.MEDIUM if confidence < 85 else LogSeverity.HIGH,
            "message": f"Anomaly detected: {anomaly_type} for user {user} (confidence: {confidence}%)",
            "source_ip": None,
            "destination_ip": dest_ip,
            "source_port": None,
            "destination_port": None,
            "username": user,
            "asset_id": asset_id,
            "raw_log": {
                "event_type": "anomaly",
                "anomaly_type": anomaly_type,
                "confidence_score": confidence,
                "baseline_deviation": random.uniform(2.0, 10.0),
                "risk_score": random.randint(40, 100),
                "contributing_factors": self._get_anomaly_factors(anomaly_type)
            },
            "indicators": {}
        }
    
    def generate_batch(
        self,
        count: int = 50,
        asset_ids: List[UUID] = None,
        weights: Dict[LogCategory, float] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate a batch of random security logs.
        
        Args:
            count: Number of logs to generate
            asset_ids: List of asset UUIDs to associate with logs
            weights: Category weights (default is balanced)
            
        Returns:
            List of security log dictionaries
        """
        # Default weights
        default_weights = {
            LogCategory.LOGIN_FAILURE: 0.25,
            LogCategory.PORT_SCAN: 0.15,
            LogCategory.MALWARE_ALERT: 0.10,
            LogCategory.PRIVILEGE_ESCALATION: 0.10,
            LogCategory.DATA_EXFILTRATION: 0.05,
            LogCategory.BRUTE_FORCE: 0.20,
            LogCategory.ANOMALY: 0.15,
        }
        weights = weights or default_weights
        
        # Generator mapping
        generators = {
            LogCategory.LOGIN_FAILURE: self.generate_login_failure,
            LogCategory.PORT_SCAN: self.generate_port_scan,
            LogCategory.MALWARE_ALERT: self.generate_malware_alert,
            LogCategory.PRIVILEGE_ESCALATION: self.generate_privilege_escalation,
            LogCategory.DATA_EXFILTRATION: self.generate_data_exfiltration,
            LogCategory.BRUTE_FORCE: self.generate_brute_force,
            LogCategory.ANOMALY: self.generate_anomaly,
        }
        
        categories = list(weights.keys())
        probabilities = list(weights.values())
        
        logs = []
        for _ in range(count):
            category = random.choices(categories, weights=probabilities, k=1)[0]
            asset_id = random.choice(asset_ids) if asset_ids else None
            
            log = generators[category](asset_id=asset_id)
            log["created_at"] = datetime.utcnow() - timedelta(
                minutes=random.randint(0, 60)
            )
            logs.append(log)
        
        logger.info("Generated log batch", count=count)
        return logs
    
    # Helper methods
    
    def _random_ip(self, internal: bool = False, malicious: bool = False) -> str:
        """Generate a random IP address."""
        if internal:
            prefix = random.choice(self.INTERNAL_IPS)
            return f"{prefix}{random.randint(1, 254)}"
        elif malicious:
            prefix = random.choice(self.MALICIOUS_IPS)
            return f"{prefix}{random.randint(1, 254)}"
        else:
            return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes to human readable."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_count < 1024:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024
        return f"{bytes_count:.1f} TB"
    
    def _get_port_for_protocol(self, protocol: str) -> int:
        """Get port for protocol."""
        ports = {
            "https": 443,
            "dns": 53,
            "ftp": 21,
            "smb": 445,
            "custom": random.randint(8000, 9000)
        }
        return ports.get(protocol, 443)
    
    def _get_port_for_service(self, service: str) -> int:
        """Get port for service."""
        ports = {
            "ssh": 22,
            "rdp": 3389,
            "smb": 445,
            "ftp": 21,
            "web_login": 443
        }
        return ports.get(service, 443)
    
    def _generate_suspicious_command(self, technique: str) -> str:
        """Generate suspicious command line."""
        commands = {
            "sudo_abuse": "sudo -u root /bin/bash",
            "setuid_binary": "./exploit_binary",
            "kernel_exploit": "./CVE-2024-0001",
            "token_manipulation": "mimikatz.exe sekurlsa::logonpasswords",
            "dll_hijacking": "rundll32.exe malicious.dll,EntryPoint",
            "service_creation": "sc create backdoor binPath=C:\\backdoor.exe",
            "scheduled_task": "schtasks /create /tn Backdoor /tr C:\\backdoor.exe",
            "pass_the_hash": "psexec.exe \\\\target -h ntlmhash"
        }
        return commands.get(technique, "unknown_command")
    
    def _get_anomaly_factors(self, anomaly_type: str) -> List[str]:
        """Get contributing factors for anomaly."""
        factors = {
            "unusual_login_time": ["login_at_3am", "weekend_access", "different_timezone"],
            "geographic_anomaly": ["new_country", "impossible_travel", "vpn_detected"],
            "data_access_spike": ["100x_normal_access", "sensitive_files", "bulk_download"],
            "process_anomaly": ["unknown_process", "suspicious_parent", "encoded_arguments"],
            "network_traffic_anomaly": ["unusual_destination", "high_volume", "encrypted_channel"],
            "user_behavior_anomaly": ["new_application", "different_role", "off_hours"]
        }
        return factors.get(anomaly_type, ["unknown_factor"])
