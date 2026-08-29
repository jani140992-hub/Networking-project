"""
Network Configuration & Security Auditing Engine:
Identifies insecure cleartext services, open management ports, and misconfigurations.
"""
from __future__ import annotations
import enum
from dataclasses import dataclass
from typing import List, Dict
from netsphere.scanner.engine import ScanResult, PortStatus


class FindingSeverity(enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFO"


@dataclass
class AuditFinding:
    rule_id: str
    title: str
    severity: FindingSeverity
    port: int
    description: str
    remediation: str


class SecurityAuditor:
    """
    Evaluates port scan results against security best practices and compliance rules.
    """
    RULES = [
        {
            "id": "SEC-001",
            "port": 23,
            "severity": FindingSeverity.CRITICAL,
            "title": "Telnet Unencrypted Remote Access Protocol Detected",
            "desc": "Telnet transmits credentials and session data in cleartext across the network.",
            "remediation": "Disable Telnet daemon and replace with SSH (port 22).",
        },
        {
            "id": "SEC-002",
            "port": 21,
            "severity": FindingSeverity.MEDIUM,
            "title": "Insecure FTP Protocol Exposed",
            "desc": "FTP passes authentication credentials without transport encryption.",
            "remediation": "Upgrade to SFTP (SSH File Transfer) or FTPS (FTP over TLS).",
        },
        {
            "id": "SEC-003",
            "port": 3389,
            "severity": FindingSeverity.HIGH,
            "title": "RDP Remote Desktop Directly Exposed",
            "desc": "Direct internet exposure of RDP is a primary vector for ransomware and brute-force attacks.",
            "remediation": "Place RDP behind a VPN, bastion host, or Zero Trust Network Access (ZTNA).",
        },
        {
            "id": "SEC-004",
            "port": 445,
            "severity": FindingSeverity.CRITICAL,
            "title": "SMB File Sharing Service Exposed",
            "desc": "Direct SMB exposure poses extreme risks of wormable lateral movement (EternalBlue / WannaCry).",
            "remediation": "Block TCP port 445 at edge firewalls immediately.",
        },
        {
            "id": "SEC-005",
            "port": 6379,
            "severity": FindingSeverity.HIGH,
            "title": "Redis In-Memory Database Exposed Without Authentication",
            "desc": "Redis instances exposed to the network often lack authentication, enabling arbitrary code execution.",
            "remediation": "Bind Redis to localhost (127.0.0.1) and enforce requirepass.",
        },
    ]

    def audit_scan_results(self, scan_results: List[ScanResult]) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        open_ports = {r.port for r in scan_results if r.status == PortStatus.OPEN}

        for rule in self.RULES:
            if rule["port"] in open_ports:
                findings.append(
                    AuditFinding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        port=rule["port"],
                        description=rule["desc"],
                        remediation=rule["remediation"],
                    )
                )

        return findings
