"""
TLS / SSL Certificate Chain and Cipher Suite Inspector.
"""
from __future__ import annotations
import socket
import ssl
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple


@dataclass
class CertificateInfo:
    subject: Dict[str, str]
    issuer: Dict[str, str]
    version: int
    serial_number: str
    not_before: str
    not_after: str
    san_list: List[str]
    cipher_suite: Tuple[str, str, int]


class TLSInspector:
    """
    Inspects SSL/TLS certificates and negotiated cipher suites.
    """
    def inspect(self, hostname: str, port: int = 443, timeout: float = 3.0) -> Optional[CertificateInfo]:
        context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.connect((hostname, port))
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

                return CertificateInfo(
                    subject=subject,
                    issuer=issuer,
                    version=cert.get("version", 0),
                    serial_number=cert.get("serialNumber", ""),
                    not_before=cert.get("notBefore", ""),
                    not_after=cert.get("notAfter", ""),
                    san_list=sans,
                    cipher_suite=cipher,
                )
        except Exception:
            return None
        finally:
            sock.close()
