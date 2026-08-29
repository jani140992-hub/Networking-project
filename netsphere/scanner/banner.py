"""
Service Banner Grabbing and Application Protocol Probing.
"""
from __future__ import annotations
import re
import socket
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class ServiceProbe:
    port: int
    protocol: str
    probe_bytes: bytes
    regex_pattern: str


class BannerGrabber:
    """
    Connects to target port, sends protocol-specific probes, and parses response banner.
    """
    PROBES = {
        80: ServiceProbe(80, "http", b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", r"Server:\s*(.+)"),
        21: ServiceProbe(21, "ftp", b"", r"^220[ -](.+)"),
        22: ServiceProbe(22, "ssh", b"", r"^SSH-[0-9.]+-([\w._-]+)"),
        25: ServiceProbe(25, "smtp", b"EHLO netsphere\r\n", r"^220[ -](.+)"),
        110: ServiceProbe(110, "pop3", b"", r"^\+OK (.+)"),
        143: ServiceProbe(143, "imap", b"", r"^\* OK (.+)"),
        6379: ServiceProbe(6379, "redis", b"PING\r\n", r"\+PONG"),
    }

    def grab_banner(self, target_ip: str, port: int, timeout: float = 1.5) -> Tuple[str, str]:
        """
        Returns (raw_banner, matched_product_or_version).
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        raw_banner = ""
        matched_info = ""

        try:
            sock.connect((target_ip, port))
            probe = self.PROBES.get(port)
            if probe and probe.probe_bytes:
                sock.sendall(probe.probe_bytes)

            data = sock.recv(2048)
            raw_banner = data.decode("utf-8", errors="replace").strip()

            if probe and probe.regex_pattern:
                m = re.search(probe.regex_pattern, raw_banner, re.MULTILINE | re.IGNORECASE)
                if m:
                    matched_info = m.group(1).strip() if m.groups() else m.group(0)
        except Exception:
            pass
        finally:
            sock.close()

        return raw_banner, matched_info
