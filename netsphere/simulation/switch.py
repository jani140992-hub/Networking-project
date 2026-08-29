"""
Layer 2 Virtual Learning Switch (Bridge) with MAC Aging and VLAN Trunking.
"""
from __future__ import annotations
import enum
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set
from netsphere.core.types import MACAddress
from netsphere.protocols.l2.ethernet import EthernetHeader


class PortMode(enum.Enum):
    ACCESS = "access"
    TRUNK = "trunk"


@dataclass
class MACEntry:
    mac_address: MACAddress
    port: str
    vlan_id: int
    timestamp: float
    is_static: bool = False


class VirtualSwitch:
    """
    Virtual Ethernet Switch:
    - Learns Source MAC addresses dynamically on ingress ports.
    - Ages out dynamic entries after MAC aging time (default 300s).
    - Filters or floods frames based on Destination MAC lookup.
    - Enforces VLAN broadcast domain isolation (Access and Trunk ports).
    """
    def __init__(self, switch_id: str = "sw1", aging_time: float = 300.0):
        self.switch_id = switch_id
        self.aging_time = aging_time
        # MAC Table key: (MACAddress, VLAN_ID) -> MACEntry
        self.mac_table: Dict[Tuple[str, int], MACEntry] = {}
        # Port Configurations: port_name -> {"mode": PortMode, "vlan": int, "allowed_vlans": Set[int]}
        self.ports: Dict[str, Dict] = {}
        self.statistics: Dict[str, int] = {
            "frames_received": 0,
            "frames_forwarded": 0,
            "frames_flooded": 0,
            "frames_dropped": 0,
        }

    def add_port(self, port_name: str, mode: PortMode = PortMode.ACCESS, default_vlan: int = 1, allowed_vlans: Optional[Set[int]] = None):
        self.ports[port_name] = {
            "mode": mode,
            "vlan": default_vlan,
            "allowed_vlans": allowed_vlans or {default_vlan},
        }

    def clean_aged_entries(self, current_time: Optional[float] = None) -> int:
        now = current_time or time.time()
        expired_keys = []
        for key, entry in self.mac_table.items():
            if not entry.is_static and (now - entry.timestamp > self.aging_time):
                expired_keys.append(key)
        for k in expired_keys:
            del self.mac_table[k]
        return len(expired_keys)

    def process_frame(self, ingress_port: str, frame_bytes: bytes, incoming_vlan: Optional[int] = None) -> List[Tuple[str, bytes]]:
        """
        Process an incoming frame on an ingress port:
        1. Validate ingress port and VLAN membership.
        2. Learn Source MAC on (Port, VLAN).
        3. Lookup Destination MAC. If unicast hit, forward to designated port; otherwise flood to eligible ports.
        Returns list of (egress_port, output_frame_bytes).
        """
        self.statistics["frames_received"] += 1
        now = time.time()

        if ingress_port not in self.ports:
            self.statistics["frames_dropped"] += 1
            return []

        port_cfg = self.ports[ingress_port]
        # Determine effective VLAN ID
        if port_cfg["mode"] == PortMode.ACCESS:
            vlan_id = port_cfg["vlan"]
        else:
            vlan_id = incoming_vlan if incoming_vlan is not None else port_cfg["vlan"]
            if vlan_id not in port_cfg["allowed_vlans"]:
                self.statistics["frames_dropped"] += 1
                return []

        if len(frame_bytes) < 14:
            self.statistics["frames_dropped"] += 1
            return []

        dst_mac = MACAddress(frame_bytes[0:6])
        src_mac = MACAddress(frame_bytes[6:12])

        # Step 2: MAC Learning
        if src_mac.is_unicast:
            self.mac_table[(str(src_mac), vlan_id)] = MACEntry(
                mac_address=src_mac,
                port=ingress_port,
                vlan_id=vlan_id,
                timestamp=now,
            )

        # Step 3: Forwarding / Flooding Decision
        if dst_mac.is_broadcast or dst_mac.is_multicast:
            # Flood frame to all other ports in this VLAN
            self.statistics["frames_flooded"] += 1
            return self._flood(ingress_port, vlan_id, frame_bytes)

        # Unicast lookup
        lookup_key = (str(dst_mac), vlan_id)
        if lookup_key in self.mac_table:
            entry = self.mac_table[lookup_key]
            # If target port is the same as arrival, filter (drop)
            if entry.port == ingress_port:
                return []
            self.statistics["frames_forwarded"] += 1
            return [(entry.port, frame_bytes)]

        # Unknown unicast -> flood
        self.statistics["frames_flooded"] += 1
        return self._flood(ingress_port, vlan_id, frame_bytes)

    def _flood(self, ingress_port: str, vlan_id: int, frame_bytes: bytes) -> List[Tuple[str, bytes]]:
        egress_targets = []
        for port_name, cfg in self.ports.items():
            if port_name == ingress_port:
                continue
            if cfg["mode"] == PortMode.ACCESS and cfg["vlan"] == vlan_id:
                egress_targets.append((port_name, frame_bytes))
            elif cfg["mode"] == PortMode.TRUNK and vlan_id in cfg["allowed_vlans"]:
                egress_targets.append((port_name, frame_bytes))
        return egress_targets
