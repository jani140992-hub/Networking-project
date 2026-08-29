"""
NetSphere: Enterprise Network Operations, Protocol Engineering & Telemetry Platform.

A comprehensive modular Python networking suite providing:
- L2-L7 protocol dissection, serialization, and state machines
- SDN topology simulation, virtual switching, and LPM routing
- Traffic shaping (Token Bucket, RED, WFQ) and TCP congestion control
- Multi-vector port scanning and OS fingerprinting
- High-precision diagnostics (Ping, Traceroute, PMTU, Bandwidth)
- NetFlow/sFlow telemetry collection and real-time anomaly detection
- Embedded REST and WebSocket operations server
- Enterprise network catalogs (IANA ports, protocols, MIBs, OUI)
"""

__version__ = "1.0.0"
__author__ = "NetSphere Engineering Team"
__license__ = "Proprietary"

from netsphere.core.types import IPv4Address, IPv6Address, MACAddress, Port, CIDRNetwork
from netsphere.core.buffer import PacketBuffer
from netsphere.core.events import EventBus

__all__ = [
    "__version__",
    "IPv4Address",
    "IPv6Address",
    "MACAddress",
    "Port",
    "CIDRNetwork",
    "PacketBuffer",
    "EventBus",
]
