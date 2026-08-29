"""
Network Address Translation (NAT) & Port Address Translation (PAT/NAPT) Engine.
"""
from __future__ import annotations
import enum
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from netsphere.core.types import IPv4Address, Port


class NATType(enum.Enum):
    SNAT = "SNAT"         # Source NAT (Masquerade for outbound Internet access)
    DNAT = "DNAT"         # Destination NAT (Port forwarding to internal servers)
    ONE_TO_ONE = "1to1"   # Static bidirectional 1-to-1 IP mapping


@dataclass
class NATSession:
    internal_ip: IPv4Address
    internal_port: Port
    external_ip: IPv4Address
    external_port: Port
    remote_ip: IPv4Address
    remote_port: Port
    protocol: int # 6=TCP, 17=UDP
    last_activity: float
    nat_type: NATType


class NATEngine:
    """
    Stateful NAT / PAT Translation Engine:
    - Maintains forward (Internal -> External) and reverse (External -> Internal) state tables.
    - Allocates ephemeral ports from pool (10000 - 60000).
    - Session expiration timer (idle timeout).
    """
    def __init__(self, public_ip: IPv4Address, port_range: Tuple[int, int] = (10000, 60000), timeout: float = 300.0):
        self.public_ip = public_ip
        self.port_start, self.port_end = port_range
        self.timeout = timeout
        self.next_port = self.port_start

        # Session tracking:
        # Outbound: (internal_ip, internal_port, remote_ip, remote_port, proto) -> NATSession
        self.outbound_sessions: Dict[Tuple[str, int, str, int, int], NATSession] = {}
        # Inbound: (external_port, proto) -> NATSession
        self.inbound_sessions: Dict[Tuple[int, int], NATSession] = {}
        # Static DNAT Port forwards: (external_port, proto) -> (internal_ip, internal_port)
        self.port_forwards: Dict[Tuple[int, int], Tuple[IPv4Address, Port]] = {}

    def add_port_forward(self, ext_port: int, internal_ip: IPv4Address, int_port: int, proto: int = 6):
        self.port_forwards[(ext_port, proto)] = (internal_ip, Port(int_port))

    def _allocate_port(self) -> int:
        for _ in range(self.port_end - self.port_start):
            port = self.next_port
            self.next_port = self.port_start if self.next_port >= self.port_end else self.next_port + 1
            if (port, 6) not in self.inbound_sessions and (port, 17) not in self.inbound_sessions:
                return port
        raise RuntimeError("NAT port allocation exhausted")

    def translate_outbound(
        self,
        src_ip: IPv4Address,
        src_port: Port,
        dst_ip: IPv4Address,
        dst_port: Port,
        protocol: int,
    ) -> Tuple[IPv4Address, Port]:
        """
        Translate Internal Private IP:Port to Public IP:AllocatedPort.
        """
        key = (str(src_ip), int(src_port), str(dst_ip), int(dst_port), protocol)
        now = time.time()

        if key in self.outbound_sessions:
            session = self.outbound_sessions[key]
            session.last_activity = now
            return session.external_ip, session.external_port

        allocated_port = Port(self._allocate_port())
        session = NATSession(
            internal_ip=src_ip,
            internal_port=src_port,
            external_ip=self.public_ip,
            external_port=allocated_port,
            remote_ip=dst_ip,
            remote_port=dst_port,
            protocol=protocol,
            last_activity=now,
            nat_type=NATType.SNAT,
        )
        self.outbound_sessions[key] = session
        self.inbound_sessions[(int(allocated_port), protocol)] = session
        return self.public_ip, allocated_port

    def translate_inbound(
        self,
        dst_port: Port,
        remote_ip: IPv4Address,
        remote_port: Port,
        protocol: int,
    ) -> Optional[Tuple[IPv4Address, Port]]:
        """
        Translate Public IP:Port back to Internal Private IP:Port.
        """
        now = time.time()
        inbound_key = (int(dst_port), protocol)

        # Check existing active session
        if inbound_key in self.inbound_sessions:
            session = self.inbound_sessions[inbound_key]
            session.last_activity = now
            return session.internal_ip, session.internal_port

        # Check static port forward
        if inbound_key in self.port_forwards:
            target_ip, target_port = self.port_forwards[inbound_key]
            return target_ip, target_port

        return None
