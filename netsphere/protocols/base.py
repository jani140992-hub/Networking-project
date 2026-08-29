"""
Base classes for Protocol Headers, Packet encapsulation, Dissectors, and Registries.
"""
from __future__ import annotations
import abc
from typing import Dict, Any, Optional, List, Type
from netsphere.core.buffer import PacketBuffer


class DissectionError(Exception):
    """Raised when parsing or dissecting a malformed network packet."""
    pass


class ProtocolHeader(abc.ABC):
    """
    Abstract base class for all protocol headers (Ethernet, IPv4, TCP, DNS, etc.).
    """
    def __init__(self, raw_data: Optional[bytes] = None):
        self._raw_data = raw_data
        self.fields: Dict[str, Any] = {}

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the protocol (e.g. 'IPv4', 'TCP')."""
        pass

    @property
    @abc.abstractmethod
    def header_length(self) -> int:
        """Length of this header in bytes."""
        pass

    @abc.abstractmethod
    def pack(self) -> bytes:
        """Serialize header into raw wire bytes."""
        pass

    @classmethod
    @abc.abstractmethod
    def unpack(cls, buffer: PacketBuffer) -> ProtocolHeader:
        """Deserialize header from a packet buffer."""
        pass

    def to_dict(self) -> Dict[str, Any]:
        """Convert header attributes to dictionary."""
        return dict(self.fields)

    def __repr__(self) -> str:
        fields_str = ", ".join(f"{k}={v}" for k, v in self.fields.items())
        return f"<{self.name}Header {fields_str}>"


class Packet:
    """
    Represents an encapsulated multi-layer network packet.
    Can contain multiple stacked protocol headers (e.g. Ethernet -> IPv4 -> TCP -> HTTP)
    and a trailing application payload.
    """
    def __init__(self, headers: Optional[List[ProtocolHeader]] = None, payload: bytes = b""):
        self.headers: List[ProtocolHeader] = headers or []
        self.payload: bytes = payload
        self.timestamp: float = 0.0

    def add_layer(self, header: ProtocolHeader) -> Packet:
        self.headers.append(header)
        return self

    def get_layer(self, header_type: Type[ProtocolHeader]) -> Optional[ProtocolHeader]:
        for h in self.headers:
            if isinstance(h, header_type):
                return h
        return None

    def has_layer(self, header_type: Type[ProtocolHeader]) -> bool:
        return self.get_layer(header_type) is not None

    def pack(self) -> bytes:
        """Serialize complete multi-layer packet from outer to inner layer."""
        buf = PacketBuffer()
        for h in self.headers:
            buf.write_bytes(h.pack())
        buf.write_bytes(self.payload)
        return buf.to_bytes()

    @property
    def total_length(self) -> int:
        return sum(h.header_length for h in self.headers) + len(self.payload)

    def summary(self) -> str:
        """Provide a one-line summary of packet layers."""
        layer_names = [h.name for h in self.headers]
        if self.payload:
            layer_names.append(f"Payload({len(self.payload)}B)")
        return " / ".join(layer_names)

    def inspect(self) -> str:
        """Return hierarchical Wireshark-like dissection view."""
        lines = [f"=== Frame: {self.total_length} bytes ==="]
        for idx, h in enumerate(self.headers, start=1):
            lines.append(f"Layer {idx}: [{h.name}]")
            for k, v in h.fields.items():
                lines.append(f"  {k}: {v}")
        if self.payload:
            lines.append(f"Payload ({len(self.payload)} bytes):")
            lines.append(PacketBuffer(self.payload).dump_hexdump())
        return "\n".join(lines)


class ProtocolDissector(abc.ABC):
    """Abstract packet dissector interface."""
    @abc.abstractmethod
    def dissect(self, buffer: PacketBuffer) -> Packet:
        pass


class ProtocolRegistry:
    """Registry mapping EtherTypes, IP Protocol numbers, and Port numbers to Protocol Classes."""
    _ethertype_map: Dict[int, Type[ProtocolHeader]] = {}
    _ip_protocol_map: Dict[int, Type[ProtocolHeader]] = {}
    _tcp_port_map: Dict[int, Type[ProtocolHeader]] = {}
    _udp_port_map: Dict[int, Type[ProtocolHeader]] = {}

    @classmethod
    def register_ethertype(cls, ethertype: int, header_cls: Type[ProtocolHeader]):
        cls._ethertype_map[ethertype] = header_cls

    @classmethod
    def register_ip_protocol(cls, proto: int, header_cls: Type[ProtocolHeader]):
        cls._ip_protocol_map[proto] = header_cls

    @classmethod
    def register_tcp_port(cls, port: int, header_cls: Type[ProtocolHeader]):
        cls._tcp_port_map[port] = header_cls

    @classmethod
    def register_udp_port(cls, port: int, header_cls: Type[ProtocolHeader]):
        cls._udp_port_map[port] = header_cls

    @classmethod
    def get_by_ethertype(cls, ethertype: int) -> Optional[Type[ProtocolHeader]]:
        return cls._ethertype_map.get(ethertype)

    @classmethod
    def get_by_ip_protocol(cls, proto: int) -> Optional[Type[ProtocolHeader]]:
        return cls._ip_protocol_map.get(proto)

    @classmethod
    def get_by_tcp_port(cls, port: int) -> Optional[Type[ProtocolHeader]]:
        return cls._tcp_port_map.get(port)

    @classmethod
    def get_by_udp_port(cls, port: int) -> Optional[Type[ProtocolHeader]]:
        return cls._udp_port_map.get(port)
