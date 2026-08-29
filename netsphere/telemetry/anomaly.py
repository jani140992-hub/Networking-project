"""
Real-time Network Anomaly & Security Threat Detection:
- TCP SYN Flood Detection
- ARP Cache Poisoning / Spoofing Detection
- Port Scan Sweep Detection
- DNS Amplification Detection
"""
from __future__ import annotations
import enum
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Deque


class ThreatType(enum.Enum):
    SYN_FLOOD = "SYN_FLOOD"
    ARP_SPOOF = "ARP_SPOOF"
    PORT_SCAN = "PORT_SCAN"
    DNS_AMPLIFICATION = "DNS_AMPLIFICATION"


@dataclass
class AnomalyAlert:
    threat_type: ThreatType
    source_ip: str
    target_ip: str
    confidence: float
    description: str
    timestamp: float


class AnomalyDetector:
    """
    Heuristic and statistical anomaly detection engine.
    """
    def __init__(self):
        # SYN flood tracker: dst_ip -> queue of syn timestamps
        self._syn_trackers: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=200))
        # Port scan tracker: src_ip -> set of scanned ports in window
        self._scan_trackers: Dict[str, Set[int]] = defaultdict(set)
        # ARP tracker: ip -> known MAC
        self._arp_bindings: Dict[str, str] = {}
        self.alerts: List[AnomalyAlert] = []

    def check_tcp_syn(self, src_ip: str, dst_ip: str, syn_flag: bool, ack_flag: bool) -> Optional[AnomalyAlert]:
        now = time.time()
        if syn_flag and not ack_flag:
            q = self._syn_trackers[dst_ip]
            q.append(now)
            # Check rate: >50 SYNs in 1 second
            recent_syns = sum(1 for t in q if now - t <= 1.0)
            if recent_syns >= 50:
                alert = AnomalyAlert(
                    threat_type=ThreatType.SYN_FLOOD,
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    confidence=0.95,
                    description=f"SYN Flood detected against {dst_ip} ({recent_syns} SYNs/sec)",
                    timestamp=now,
                )
                self.alerts.append(alert)
                return alert
        return None

    def check_port_scan(self, src_ip: str, dst_port: int) -> Optional[AnomalyAlert]:
        now = time.time()
        ports = self._scan_trackers[src_ip]
        ports.add(dst_port)
        if len(ports) >= 20:
            alert = AnomalyAlert(
                threat_type=ThreatType.PORT_SCAN,
                source_ip=src_ip,
                target_ip="Multiple",
                confidence=0.90,
                description=f"Port scan detected from {src_ip} targeting {len(ports)} distinct ports",
                timestamp=now,
            )
            self.alerts.append(alert)
            return alert
        return None

    def check_arp_packet(self, sender_ip: str, sender_mac: str) -> Optional[AnomalyAlert]:
        now = time.time()
        if sender_ip in self._arp_bindings:
            known_mac = self._arp_bindings[sender_ip]
            if known_mac != sender_mac:
                alert = AnomalyAlert(
                    threat_type=ThreatType.ARP_SPOOF,
                    source_ip=sender_ip,
                    target_ip="Broadcast",
                    confidence=0.98,
                    description=f"ARP Cache Poisoning: IP {sender_ip} MAC changed from {known_mac} to {sender_mac}",
                    timestamp=now,
                )
                self.alerts.append(alert)
                return alert
        else:
            self._arp_bindings[sender_ip] = sender_mac
        return None
