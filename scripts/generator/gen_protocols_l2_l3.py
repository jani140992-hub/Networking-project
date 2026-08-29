"""
NetSphere Protocols Generator: Base, Layer 2 (Data Link) and Layer 3 (Network).
"""
from common import write_code_file

def generate_protocols_l2_l3():
    total_lines = 0
    print("[*] Generating NetSphere Protocol Base, L2 & L3 modules...")

    # netsphere/protocols/__init__.py
    content_proto_init = '''"""
NetSphere Protocol Engineering & Dissection Engine.
Encapsulates OSI L2 through L7 protocol dissectors, serializers, and validators.
"""
from netsphere.protocols.base import (
    ProtocolHeader,
    Packet,
    ProtocolDissector,
    DissectionError,
    ProtocolRegistry,
)

__all__ = [
    "ProtocolHeader",
    "Packet",
    "ProtocolDissector",
    "DissectionError",
    "ProtocolRegistry",
]
'''
    total_lines += write_code_file("netsphere/protocols/__init__.py", content_proto_init)

    # netsphere/protocols/base.py
    content_proto_base = '''"""
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
        return "\\n".join(lines)


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
'''
    total_lines += write_code_file("netsphere/protocols/base.py", content_proto_base)

    # netsphere/protocols/l2/__init__.py
    content_l2_init = '''"""
OSI Layer 2 (Data Link) Protocol implementations.
"""
from netsphere.protocols.l2.ethernet import EthernetHeader, EthernetFrame
from netsphere.protocols.l2.arp import ARPHeader, ARPOperation
from netsphere.protocols.l2.vlan import VLANHeader, QinQHeader
from netsphere.protocols.l2.stp import STPHeader, BPDUType
from netsphere.protocols.l2.lldp import LLDPHeader, LLDPTLV

__all__ = [
    "EthernetHeader",
    "EthernetFrame",
    "ARPHeader",
    "ARPOperation",
    "VLANHeader",
    "QinQHeader",
    "STPHeader",
    "BPDUType",
    "LLDPHeader",
    "LLDPTLV",
]
'''
    total_lines += write_code_file("netsphere/protocols/l2/__init__.py", content_l2_init)

    # netsphere/protocols/l2/ethernet.py
    content_ethernet = '''"""
IEEE 802.3 and Ethernet II Frame header implementation.
"""
from __future__ import annotations
import struct
from typing import Optional
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import MACAddress, EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class EthernetHeader(ProtocolHeader):
    """
    Standard Ethernet II Header (14 bytes):
    - Destination MAC (6 bytes)
    - Source MAC (6 bytes)
    - EtherType (2 bytes)
    """
    def __init__(
        self,
        dst_mac: MACAddress = MACAddress("ff:ff:ff:ff:ff:ff"),
        src_mac: MACAddress = MACAddress("00:00:00:00:00:00"),
        ethertype: int = EtherType.IPV4,
    ):
        super().__init__()
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.ethertype = ethertype
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "dst_mac": str(self.dst_mac),
            "src_mac": str(self.src_mac),
            "ethertype": f"0x{self.ethertype:04x}",
            "ethertype_name": EtherType(self.ethertype).name if self.ethertype in EtherType._value2member_map_ else "UNKNOWN",
        }

    @property
    def name(self) -> str:
        return "Ethernet"

    @property
    def header_length(self) -> int:
        return 14

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_bytes(self.dst_mac.raw_bytes)
        buf.write_bytes(self.src_mac.raw_bytes)
        buf.write_uint16_be(self.ethertype)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> EthernetHeader:
        if buffer.remaining < 14:
            raise DissectionError(f"Buffer underflow unpacking EthernetHeader (need 14, got {buffer.remaining})")
        dst_bytes = buffer.read_bytes(6)
        src_bytes = buffer.read_bytes(6)
        ethertype = buffer.read_uint16_be()
        return cls(dst_mac=MACAddress(dst_bytes), src_mac=MACAddress(src_bytes), ethertype=ethertype)


class EthernetFrame:
    """Represents a complete Ethernet Frame including FCS (Frame Check Sequence)."""
    def __init__(self, header: EthernetHeader, payload: bytes, fcs: Optional[int] = None):
        self.header = header
        self.payload = payload
        self.fcs = fcs

    def pack(self, include_fcs: bool = False) -> bytes:
        raw = self.header.pack() + self.payload
        if include_fcs:
            from netsphere.core.checksum import calculate_crc32
            fcs_val = calculate_crc32(raw)
            return raw + struct.pack("!I", fcs_val)
        return raw
'''
    total_lines += write_code_file("netsphere/protocols/l2/ethernet.py", content_ethernet)

    # netsphere/protocols/l2/arp.py
    content_arp = '''"""
Address Resolution Protocol (ARP / RARP - RFC 826).
"""
from __future__ import annotations
import enum
import struct
from typing import Optional
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import MACAddress, IPv4Address, EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class ARPOperation(enum.IntEnum):
    REQUEST = 1
    REPLY = 2
    RARP_REQUEST = 3
    RARP_REPLY = 4
    DRARP_REQUEST = 5
    DRARP_REPLY = 6
    DRARP_ERROR = 7
    IN_ARP_REQUEST = 8
    IN_ARP_REPLY = 9


class ARPHeader(ProtocolHeader):
    """
    Ethernet / IPv4 ARP Packet (28 bytes):
    - Hardware Type: 1 (Ethernet)
    - Protocol Type: 0x0800 (IPv4)
    - Hardware Size: 6
    - Protocol Size: 4
    - Opcode: 1=Request, 2=Reply
    - Sender MAC: 6 bytes
    - Sender IP: 4 bytes
    - Target MAC: 6 bytes
    - Target IP: 4 bytes
    """
    def __init__(
        self,
        operation: ARPOperation = ARPOperation.REQUEST,
        sender_mac: MACAddress = MACAddress("00:00:00:00:00:00"),
        sender_ip: IPv4Address = IPv4Address("0.0.0.0"),
        target_mac: MACAddress = MACAddress("00:00:00:00:00:00"),
        target_ip: IPv4Address = IPv4Address("0.0.0.0"),
        hw_type: int = 1,
        proto_type: int = EtherType.IPV4,
    ):
        super().__init__()
        self.hw_type = hw_type
        self.proto_type = proto_type
        self.hw_size = 6
        self.proto_size = 4
        self.operation = operation
        self.sender_mac = sender_mac
        self.sender_ip = sender_ip
        self.target_mac = target_mac
        self.target_ip = target_ip
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "hw_type": self.hw_type,
            "proto_type": f"0x{self.proto_type:04x}",
            "hw_size": self.hw_size,
            "proto_size": self.proto_size,
            "operation": f"{self.operation.name} ({self.operation.value})",
            "sender_mac": str(self.sender_mac),
            "sender_ip": str(self.sender_ip),
            "target_mac": str(self.target_mac),
            "target_ip": str(self.target_ip),
        }

    @property
    def name(self) -> str:
        return "ARP"

    @property
    def header_length(self) -> int:
        return 28

    @property
    def is_gratuitous(self) -> bool:
        """Check if this is a Gratuitous ARP (Sender IP == Target IP)."""
        return self.sender_ip == self.target_ip

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint16_be(self.hw_type)
        buf.write_uint16_be(self.proto_type)
        buf.write_uint8(self.hw_size)
        buf.write_uint8(self.proto_size)
        buf.write_uint16_be(int(self.operation))
        buf.write_bytes(self.sender_mac.raw_bytes)
        buf.write_bytes(self.sender_ip.packed)
        buf.write_bytes(self.target_mac.raw_bytes)
        buf.write_bytes(self.target_ip.packed)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> ARPHeader:
        if buffer.remaining < 28:
            raise DissectionError("Buffer underflow unpacking ARPHeader")
        hw_type = buffer.read_uint16_be()
        proto_type = buffer.read_uint16_be()
        hw_size = buffer.read_uint8()
        proto_size = buffer.read_uint8()
        opcode_val = buffer.read_uint16_be()
        operation = ARPOperation(opcode_val) if opcode_val in ARPOperation._value2member_map_ else ARPOperation.REQUEST

        sender_mac = MACAddress(buffer.read_bytes(hw_size))
        sender_ip = IPv4Address(buffer.read_bytes(proto_size))
        target_mac = MACAddress(buffer.read_bytes(hw_size))
        target_ip = IPv4Address(buffer.read_bytes(proto_size))

        return cls(
            operation=operation,
            sender_mac=sender_mac,
            sender_ip=sender_ip,
            target_mac=target_mac,
            target_ip=target_ip,
            hw_type=hw_type,
            proto_type=proto_type,
        )


# Register ARP with ProtocolRegistry
ProtocolRegistry.register_ethertype(EtherType.ARP, ARPHeader)
'''
    total_lines += write_code_file("netsphere/protocols/l2/arp.py", content_arp)

    # netsphere/protocols/l2/vlan.py
    content_vlan = '''"""
IEEE 802.1Q (VLAN Tagging) and IEEE 802.1ad (QinQ Provider Bridging).
"""
from __future__ import annotations
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class VLANHeader(ProtocolHeader):
    """
    IEEE 802.1Q Tag Control Information (4 bytes):
    - TPID (Tag Protocol Identifier): 0x8100 (2 bytes)
    - TCI (Tag Control Info): 2 bytes:
        - PCP (Priority Code Point): 3 bits
        - DEI (Drop Eligible Indicator): 1 bit
        - VID (VLAN Identifier): 12 bits (1 - 4094)
    - Next EtherType: 2 bytes
    """
    def __init__(
        self,
        vlan_id: int = 1,
        priority: int = 0,
        drop_eligible: bool = False,
        next_ethertype: int = EtherType.IPV4,
    ):
        super().__init__()
        if not 0 <= vlan_id <= 4095:
            raise ValueError(f"Invalid VLAN ID: {vlan_id} (must be 0-4095)")
        if not 0 <= priority <= 7:
            raise ValueError(f"Priority (PCP) must be 0-7, got {priority}")
        self.vlan_id = vlan_id
        self.priority = priority
        self.drop_eligible = drop_eligible
        self.next_ethertype = next_ethertype
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "vlan_id": self.vlan_id,
            "priority": self.priority,
            "drop_eligible": self.drop_eligible,
            "next_ethertype": f"0x{self.next_ethertype:04x}",
        }

    @property
    def name(self) -> str:
        return "802.1Q"

    @property
    def header_length(self) -> int:
        return 4

    def pack(self) -> bytes:
        tci = (self.priority << 13) | ((1 if self.drop_eligible else 0) << 12) | (self.vlan_id & 0x0FFF)
        buf = PacketBuffer()
        buf.write_uint16_be(tci)
        buf.write_uint16_be(self.next_ethertype)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> VLANHeader:
        if buffer.remaining < 4:
            raise DissectionError("Buffer underflow unpacking VLANHeader")
        tci = buffer.read_uint16_be()
        priority = (tci >> 13) & 0x07
        drop_eligible = bool((tci >> 12) & 0x01)
        vlan_id = tci & 0x0FFF
        next_ethertype = buffer.read_uint16_be()
        return cls(vlan_id=vlan_id, priority=priority, drop_eligible=drop_eligible, next_ethertype=next_ethertype)


class QinQHeader(ProtocolHeader):
    """
    IEEE 802.1ad QinQ Header (Outer Service VLAN 0x88a8 + Inner Customer VLAN 0x8100).
    """
    def __init__(self, service_vlan: int = 100, customer_vlan: int = 10, next_ethertype: int = EtherType.IPV4):
        super().__init__()
        self.outer_vlan = VLANHeader(vlan_id=service_vlan, next_ethertype=EtherType.VLAN_8021Q)
        self.inner_vlan = VLANHeader(vlan_id=customer_vlan, next_ethertype=next_ethertype)
        self.fields = {
            "service_vlan": service_vlan,
            "customer_vlan": customer_vlan,
            "next_ethertype": f"0x{next_ethertype:04x}",
        }

    @property
    def name(self) -> str:
        return "QinQ"

    @property
    def header_length(self) -> int:
        return 8

    def pack(self) -> bytes:
        return self.outer_vlan.pack() + self.inner_vlan.pack()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> QinQHeader:
        if buffer.remaining < 8:
            raise DissectionError("Buffer underflow unpacking QinQHeader")
        outer = VLANHeader.unpack(buffer)
        inner = VLANHeader.unpack(buffer)
        return cls(service_vlan=outer.vlan_id, customer_vlan=inner.vlan_id, next_ethertype=inner.next_ethertype)


ProtocolRegistry.register_ethertype(EtherType.VLAN_8021Q, VLANHeader)
ProtocolRegistry.register_ethertype(EtherType.IEEE_8021AD_QINQ, QinQHeader)
'''
    total_lines += write_code_file("netsphere/protocols/l2/vlan.py", content_vlan)

    # netsphere/protocols/l2/stp.py
    content_stp = '''"""
IEEE 802.1D Spanning Tree Protocol (STP) and Rapid Spanning Tree Protocol (RSTP).
"""
from __future__ import annotations
import enum
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import MACAddress
from netsphere.protocols.base import ProtocolHeader, DissectionError


class BPDUType(enum.IntEnum):
    CONFIGURATION = 0x00
    TOPOLOGY_CHANGE_NOTIFICATION = 0x80
    RAPID_STP = 0x02


class STPHeader(ProtocolHeader):
    """
    STP BPDU (Bridge Protocol Data Unit):
    - Protocol Identifier: 0x0000 (2 bytes)
    - Protocol Version: 0 (STP) or 2 (RSTP) (1 byte)
    - BPDU Type: 0x00 Config, 0x80 TCN (1 byte)
    - Flags: 1 byte (TC, Proposal, Port Role, Learning, Forwarding, Agreement, TCA)
    - Root Identifier: 8 bytes (Priority 2 bytes + Root MAC 6 bytes)
    - Root Path Cost: 4 bytes
    - Bridge Identifier: 8 bytes (Priority 2 bytes + Bridge MAC 6 bytes)
    - Port Identifier: 2 bytes
    - Message Age: 2 bytes (units 1/256 sec)
    - Max Age: 2 bytes
    - Hello Time: 2 bytes
    - Forward Delay: 2 bytes
    """
    def __init__(
        self,
        bpdu_type: BPDUType = BPDUType.CONFIGURATION,
        root_priority: int = 32768,
        root_mac: MACAddress = MACAddress("00:00:00:00:00:01"),
        root_path_cost: int = 0,
        bridge_priority: int = 32768,
        bridge_mac: MACAddress = MACAddress("00:00:00:00:00:01"),
        port_id: int = 0x8001,
        message_age: int = 0,
        max_age: int = 20 * 256,
        hello_time: int = 2 * 256,
        forward_delay: int = 15 * 256,
    ):
        super().__init__()
        self.protocol_id = 0x0000
        self.version = 0
        self.bpdu_type = bpdu_type
        self.flags = 0
        self.root_priority = root_priority
        self.root_mac = root_mac
        self.root_path_cost = root_path_cost
        self.bridge_priority = bridge_priority
        self.bridge_mac = bridge_mac
        self.port_id = port_id
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "bpdu_type": self.bpdu_type.name,
            "root_id": f"{self.root_priority} / {self.root_mac}",
            "path_cost": self.root_path_cost,
            "bridge_id": f"{self.bridge_priority} / {self.bridge_mac}",
            "port_id": f"0x{self.port_id:04x}",
            "hello_time_sec": self.hello_time / 256.0,
            "max_age_sec": self.max_age / 256.0,
            "forward_delay_sec": self.forward_delay / 256.0,
        }

    @property
    def name(self) -> str:
        return "STP"

    @property
    def header_length(self) -> int:
        return 35 if self.bpdu_type != BPDUType.TOPOLOGY_CHANGE_NOTIFICATION else 4

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint16_be(self.protocol_id)
        buf.write_uint8(self.version)
        buf.write_uint8(int(self.bpdu_type))
        if self.bpdu_type == BPDUType.TOPOLOGY_CHANGE_NOTIFICATION:
            return buf.to_bytes()

        buf.write_uint8(self.flags)
        buf.write_uint16_be(self.root_priority)
        buf.write_bytes(self.root_mac.raw_bytes)
        buf.write_uint32_be(self.root_path_cost)
        buf.write_uint16_be(self.bridge_priority)
        buf.write_bytes(self.bridge_mac.raw_bytes)
        buf.write_uint16_be(self.port_id)
        buf.write_uint16_be(self.message_age)
        buf.write_uint16_be(self.max_age)
        buf.write_uint16_be(self.hello_time)
        buf.write_uint16_be(self.forward_delay)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> STPHeader:
        if buffer.remaining < 4:
            raise DissectionError("Buffer underflow unpacking STP")
        _proto = buffer.read_uint16_be()
        _ver = buffer.read_uint8()
        b_type = buffer.read_uint8()
        bpdu_type = BPDUType(b_type) if b_type in BPDUType._value2member_map_ else BPDUType.CONFIGURATION

        if bpdu_type == BPDUType.TOPOLOGY_CHANGE_NOTIFICATION:
            return cls(bpdu_type=bpdu_type)

        if buffer.remaining < 31:
            raise DissectionError("Buffer underflow unpacking STP Configuration BPDU")
        _flags = buffer.read_uint8()
        root_pri = buffer.read_uint16_be()
        root_mac = MACAddress(buffer.read_bytes(6))
        cost = buffer.read_uint32_be()
        bridge_pri = buffer.read_uint16_be()
        bridge_mac = MACAddress(buffer.read_bytes(6))
        port_id = buffer.read_uint16_be()
        msg_age = buffer.read_uint16_be()
        max_age = buffer.read_uint16_be()
        hello = buffer.read_uint16_be()
        fwd_delay = buffer.read_uint16_be()

        return cls(
            bpdu_type=bpdu_type,
            root_priority=root_pri,
            root_mac=root_mac,
            root_path_cost=cost,
            bridge_priority=bridge_pri,
            bridge_mac=bridge_mac,
            port_id=port_id,
            message_age=msg_age,
            max_age=max_age,
            hello_time=hello,
            forward_delay=fwd_delay,
        )
'''
    total_lines += write_code_file("netsphere/protocols/l2/stp.py", content_stp)

    # netsphere/protocols/l2/lldp.py
    content_lldp = '''"""
IEEE 802.1AB Link Layer Discovery Protocol (LLDP).
"""
from __future__ import annotations
import enum
from typing import List, Tuple
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class LLDPTLVType(enum.IntEnum):
    END_OF_LLDPDU = 0
    CHASSIS_ID = 1
    PORT_ID = 2
    TIME_TO_LIVE = 3
    PORT_DESCRIPTION = 4
    SYSTEM_NAME = 5
    SYSTEM_DESCRIPTION = 6
    SYSTEM_CAPABILITIES = 7
    MANAGEMENT_ADDRESS = 8
    ORGANIZATION_SPECIFIC = 127


class LLDPTLV:
    """Represents an LLDP Type-Length-Value field."""
    def __init__(self, tlv_type: int, value: bytes):
        self.tlv_type = tlv_type
        self.value = value

    @property
    def length(self) -> int:
        return len(self.value)

    def pack(self) -> bytes:
        # Type is 7 bits, Length is 9 bits
        type_len = ((self.tlv_type & 0x7F) << 9) | (len(self.value) & 0x01FF)
        buf = PacketBuffer()
        buf.write_uint16_be(type_len)
        buf.write_bytes(self.value)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> LLDPTLV:
        if buffer.remaining < 2:
            raise DissectionError("Buffer underflow unpacking LLDP TLV")
        type_len = buffer.read_uint16_be()
        tlv_type = (type_len >> 9) & 0x7F
        length = type_len & 0x01FF
        if buffer.remaining < length:
            raise DissectionError(f"Buffer underflow unpacking LLDP TLV value (need {length}, got {buffer.remaining})")
        val = buffer.read_bytes(length)
        return cls(tlv_type, val)


class LLDPHeader(ProtocolHeader):
    """
    LLDP Frame payload containing mandatory and optional TLVs:
    - Mandatory: Chassis ID, Port ID, TTL, End of LLDPDU
    """
    def __init__(self, tlvs: Optional[List[LLDPTLV]] = None):
        super().__init__()
        self.tlvs: List[LLDPTLV] = tlvs or []
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "tlv_count": len(self.tlvs),
            "tlv_types": [LLDPTLVType(t.tlv_type).name if t.tlv_type in LLDPTLVType._value2member_map_ else f"Custom({t.tlv_type})" for t in self.tlvs],
        }

    @property
    def name(self) -> str:
        return "LLDP"

    @property
    def header_length(self) -> int:
        return sum(2 + t.length for t in self.tlvs)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        for t in self.tlvs:
            buf.write_bytes(t.pack())
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> LLDPHeader:
        tlvs = []
        while buffer.remaining >= 2:
            tlv = LLDPTLV.unpack(buffer)
            tlvs.append(tlv)
            if tlv.tlv_type == LLDPTLVType.END_OF_LLDPDU:
                break
        return cls(tlvs)


ProtocolRegistry.register_ethertype(EtherType.LLDP, LLDPHeader)
'''
    total_lines += write_code_file("netsphere/protocols/l2/lldp.py", content_lldp)

    # netsphere/protocols/l3/__init__.py
    content_l3_init = '''"""
OSI Layer 3 (Network Layer) Protocol implementations.
"""
from netsphere.protocols.l3.ipv4 import IPv4Header, IPv4Flags
from netsphere.protocols.l3.ipv6 import IPv6Header, IPv6ExtensionHeader
from netsphere.protocols.l3.icmp import ICMPHeader, ICMPType, ICMPCode
from netsphere.protocols.l3.icmpv6 import ICMPv6Header, ICMPv6Type
from netsphere.protocols.l3.igmp import IGMPHeader, IGMPType
from netsphere.protocols.l3.ipsec import AHHeader, ESPHeader
from netsphere.protocols.l3.gre import GREHeader

__all__ = [
    "IPv4Header",
    "IPv4Flags",
    "IPv6Header",
    "IPv6ExtensionHeader",
    "ICMPHeader",
    "ICMPType",
    "ICMPCode",
    "ICMPv6Header",
    "ICMPv6Type",
    "IGMPHeader",
    "IGMPType",
    "AHHeader",
    "ESPHeader",
    "GREHeader",
]
'''
    total_lines += write_code_file("netsphere/protocols/l3/__init__.py", content_l3_init)

    # netsphere/protocols/l3/ipv4.py
    content_ipv4 = '''"""
Internet Protocol Version 4 (IPv4 - RFC 791).
"""
from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import Optional, List
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address, TransportProtocol, EtherType
from netsphere.core.checksum import calculate_internet_checksum
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


@dataclass
class IPv4Flags:
    reserved: bool = False
    dont_fragment: bool = False
    more_fragments: bool = False

    def to_int(self) -> int:
        val = 0
        if self.reserved:
            val |= 0x4
        if self.dont_fragment:
            val |= 0x2
        if self.more_fragments:
            val |= 0x1
        return val

    @classmethod
    def from_int(cls, val: int) -> IPv4Flags:
        return cls(
            reserved=bool(val & 0x4),
            dont_fragment=bool(val & 0x2),
            more_fragments=bool(val & 0x1),
        )


class IPv4Header(ProtocolHeader):
    """
    IPv4 Header format (20 bytes standard, up to 60 bytes with options):
    - Version (4 bits) + IHL (4 bits)
    - DSCP (6 bits) + ECN (2 bits) [TOS]
    - Total Length (16 bits)
    - Identification (16 bits)
    - Flags (3 bits) + Fragment Offset (13 bits)
    - Time To Live (8 bits)
    - Protocol (8 bits)
    - Header Checksum (16 bits)
    - Source IP (32 bits)
    - Destination IP (32 bits)
    - Options (variable, 0-40 bytes)
    """
    def __init__(
        self,
        src_ip: IPv4Address = IPv4Address("127.0.0.1"),
        dst_ip: IPv4Address = IPv4Address("127.0.0.1"),
        protocol: int = TransportProtocol.TCP,
        ttl: int = 64,
        identification: int = 0x1234,
        flags: Optional[IPv4Flags] = None,
        fragment_offset: int = 0,
        dscp: int = 0,
        ecn: int = 0,
        total_length: int = 20,
        options: bytes = b"",
    ):
        super().__init__()
        self.version = 4
        self.ihl = 5 + (len(options) + 3) // 4
        self.dscp = dscp
        self.ecn = ecn
        self.total_length = total_length
        self.identification = identification
        self.flags = flags or IPv4Flags(dont_fragment=True)
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.options = options
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "version": self.version,
            "ihl": self.ihl,
            "tos": f"DSCP={self.dscp}, ECN={self.ecn}",
            "total_length": self.total_length,
            "id": f"0x{self.identification:04x}",
            "flags": f"DF={int(self.flags.dont_fragment)}, MF={int(self.flags.more_fragments)}",
            "fragment_offset": self.fragment_offset,
            "ttl": self.ttl,
            "protocol": f"{TransportProtocol(self.protocol).name if self.protocol in TransportProtocol._value2member_map_ else self.protocol}",
            "checksum": f"0x{self.checksum:04x}",
            "src_ip": str(self.src_ip),
            "dst_ip": str(self.dst_ip),
        }

    @property
    def name(self) -> str:
        return "IPv4"

    @property
    def header_length(self) -> int:
        return self.ihl * 4

    def compute_checksum(self) -> int:
        """Compute the RFC 791 16-bit one's complement header checksum."""
        # Pack header with checksum field zeroed
        hdr_bytes = self._pack_with_checksum(0)
        return calculate_internet_checksum(hdr_bytes)

    def _pack_with_checksum(self, csum: int) -> bytes:
        buf = PacketBuffer()
        ver_ihl = (self.version << 4) | (self.ihl & 0x0F)
        tos = ((self.dscp & 0x3F) << 2) | (self.ecn & 0x03)
        buf.write_uint8(ver_ihl)
        buf.write_uint8(tos)
        buf.write_uint16_be(self.total_length)
        buf.write_uint16_be(self.identification)

        flags_offset = (self.flags.to_int() << 13) | (self.fragment_offset & 0x1FFF)
        buf.write_uint16_be(flags_offset)
        buf.write_uint8(self.ttl)
        buf.write_uint8(self.protocol)
        buf.write_uint16_be(csum)
        buf.write_bytes(self.src_ip.packed)
        buf.write_bytes(self.dst_ip.packed)
        if self.options:
            buf.write_bytes(self.options)
            pad_len = (self.ihl * 4) - 20 - len(self.options)
            if pad_len > 0:
                buf.write_bytes(b"\\x00" * pad_len)
        return buf.to_bytes()

    def pack(self) -> bytes:
        calculated_csum = self.compute_checksum()
        self.checksum = calculated_csum
        self._sync_fields()
        return self._pack_with_checksum(calculated_csum)

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> IPv4Header:
        if buffer.remaining < 20:
            raise DissectionError("Buffer underflow unpacking IPv4Header")
        ver_ihl = buffer.read_uint8()
        version = (ver_ihl >> 4) & 0x0F
        ihl = ver_ihl & 0x0F
        if version != 4:
            raise DissectionError(f"Invalid IPv4 version: {version}")
        if ihl < 5:
            raise DissectionError(f"Invalid IPv4 IHL: {ihl} (minimum 5)")

        tos = buffer.read_uint8()
        dscp = (tos >> 2) & 0x3F
        ecn = tos & 0x03
        total_len = buffer.read_uint16_be()
        identification = buffer.read_uint16_be()

        flags_offset = buffer.read_uint16_be()
        flags = IPv4Flags.from_int((flags_offset >> 13) & 0x07)
        frag_offset = flags_offset & 0x1FFF

        ttl = buffer.read_uint8()
        protocol = buffer.read_uint8()
        checksum = buffer.read_uint16_be()

        src_ip = IPv4Address(buffer.read_bytes(4))
        dst_ip = IPv4Address(buffer.read_bytes(4))

        options = b""
        opt_len = (ihl - 5) * 4
        if opt_len > 0:
            if buffer.remaining < opt_len:
                raise DissectionError("Buffer underflow reading IPv4 options")
            options = buffer.read_bytes(opt_len)

        hdr = cls(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            ttl=ttl,
            identification=identification,
            flags=flags,
            fragment_offset=frag_offset,
            dscp=dscp,
            ecn=ecn,
            total_length=total_len,
            options=options,
        )
        hdr.checksum = checksum
        hdr._sync_fields()
        return hdr


ProtocolRegistry.register_ethertype(EtherType.IPV4, IPv4Header)
'''
    total_lines += write_code_file("netsphere/protocols/l3/ipv4.py", content_ipv4)

    # netsphere/protocols/l3/ipv6.py
    content_ipv6 = '''"""
Internet Protocol Version 6 (IPv6 - RFC 8200).
"""
from __future__ import annotations
from typing import Optional, List
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv6Address, TransportProtocol, EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class IPv6ExtensionHeader(ProtocolHeader):
    """Base class for IPv6 Extension Headers (Hop-by-Hop, Routing, Fragment, etc.)."""
    def __init__(self, next_header: int = 59, length: int = 0, data: bytes = b""):
        super().__init__()
        self.next_header = next_header
        self.hdr_ext_len = length
        self.data = data
        self.fields = {"next_header": next_header, "length": length}

    @property
    def name(self) -> str:
        return "IPv6Extension"

    @property
    def header_length(self) -> int:
        return (self.hdr_ext_len + 1) * 8

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(self.next_header)
        buf.write_uint8(self.hdr_ext_len)
        buf.write_bytes(self.data)
        pad = self.header_length - 2 - len(self.data)
        if pad > 0:
            buf.write_bytes(b"\\x00" * pad)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> IPv6ExtensionHeader:
        if buffer.remaining < 2:
            raise DissectionError("Buffer underflow unpacking IPv6ExtensionHeader")
        nxt = buffer.read_uint8()
        ext_len = buffer.read_uint8()
        total_len = (ext_len + 1) * 8
        payload_len = total_len - 2
        if buffer.remaining < payload_len:
            raise DissectionError("Buffer underflow unpacking IPv6Extension data")
        data = buffer.read_bytes(payload_len)
        return cls(next_header=nxt, length=ext_len, data=data)


class IPv6Header(ProtocolHeader):
    """
    Fixed 40-byte IPv6 Header (RFC 8200):
    - Version (4 bits)
    - Traffic Class (8 bits)
    - Flow Label (20 bits)
    - Payload Length (16 bits)
    - Next Header (8 bits)
    - Hop Limit (8 bits)
    - Source Address (128 bits)
    - Destination Address (128 bits)
    """
    def __init__(
        self,
        src_ip: IPv6Address = IPv6Address("::1"),
        dst_ip: IPv6Address = IPv6Address("::1"),
        next_header: int = TransportProtocol.TCP,
        hop_limit: int = 64,
        traffic_class: int = 0,
        flow_label: int = 0,
        payload_length: int = 0,
    ):
        super().__init__()
        self.version = 6
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.payload_length = payload_length
        self.next_header = next_header
        self.hop_limit = hop_limit
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.extensions: List[IPv6ExtensionHeader] = []
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "version": self.version,
            "traffic_class": self.traffic_class,
            "flow_label": f"0x{self.flow_label:05x}",
            "payload_length": self.payload_length,
            "next_header": f"{TransportProtocol(self.next_header).name if self.next_header in TransportProtocol._value2member_map_ else self.next_header}",
            "hop_limit": self.hop_limit,
            "src_ip": str(self.src_ip),
            "dst_ip": str(self.dst_ip),
        }

    @property
    def name(self) -> str:
        return "IPv6"

    @property
    def header_length(self) -> int:
        return 40 + sum(ext.header_length for ext in self.extensions)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        # 32-bit: Version (4) + Traffic Class (8) + Flow Label (20)
        v_tc_fl = (self.version << 28) | ((self.traffic_class & 0xFF) << 20) | (self.flow_label & 0x0FFFFF)
        buf.write_uint32_be(v_tc_fl)
        buf.write_uint16_be(self.payload_length)
        buf.write_uint8(self.next_header)
        buf.write_uint8(self.hop_limit)
        buf.write_bytes(self.src_ip.packed)
        buf.write_bytes(self.dst_ip.packed)
        for ext in self.extensions:
            buf.write_bytes(ext.pack())
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> IPv6Header:
        if buffer.remaining < 40:
            raise DissectionError("Buffer underflow unpacking IPv6Header")
        v_tc_fl = buffer.read_uint32_be()
        ver = (v_tc_fl >> 28) & 0x0F
        if ver != 6:
            raise DissectionError(f"Invalid IPv6 version: {ver}")
        tc = (v_tc_fl >> 20) & 0xFF
        fl = v_tc_fl & 0x0FFFFF

        payload_len = buffer.read_uint16_be()
        next_hdr = buffer.read_uint8()
        hop_limit = buffer.read_uint8()
        src = IPv6Address(buffer.read_bytes(16))
        dst = IPv6Address(buffer.read_bytes(16))

        return cls(
            src_ip=src,
            dst_ip=dst,
            next_header=next_hdr,
            hop_limit=hop_limit,
            traffic_class=tc,
            flow_label=fl,
            payload_length=payload_len,
        )


ProtocolRegistry.register_ethertype(EtherType.IPV6, IPv6Header)
'''
    total_lines += write_code_file("netsphere/protocols/l3/ipv6.py", content_ipv6)

    # netsphere/protocols/l3/icmp.py
    content_icmp = '''"""
Internet Control Message Protocol (ICMPv4 - RFC 792).
"""
from __future__ import annotations
import enum
import struct
from typing import Optional
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import TransportProtocol
from netsphere.core.checksum import calculate_internet_checksum
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class ICMPType(enum.IntEnum):
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    SOURCE_QUENCH = 4
    REDIRECT = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP_REQUEST = 13
    TIMESTAMP_REPLY = 14
    INFO_REQUEST = 15
    INFO_REPLY = 16
    ADDRESS_MASK_REQUEST = 17
    ADDRESS_MASK_REPLY = 18


class ICMPCode(enum.IntEnum):
    # Destination Unreachable codes
    NET_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3
    FRAGMENTATION_NEEDED = 4
    SOURCE_ROUTE_FAILED = 5
    DEST_NET_UNKNOWN = 6
    DEST_HOST_UNKNOWN = 7
    # Time Exceeded codes
    TTL_EXPIRED_IN_TRANSIT = 0
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1


class ICMPHeader(ProtocolHeader):
    """
    ICMP Header (8 bytes):
    - Type (8 bits)
    - Code (8 bits)
    - Checksum (16 bits)
    - Rest of Header / ID & Sequence (32 bits)
    """
    def __init__(
        self,
        icmp_type: ICMPType = ICMPType.ECHO_REQUEST,
        code: int = 0,
        identifier: int = 0,
        sequence_number: int = 0,
        rest_of_header: int = 0,
    ):
        super().__init__()
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = 0
        self.identifier = identifier
        self.sequence_number = sequence_number
        self.rest_of_header = rest_of_header
        self._sync_fields()

    def _sync_fields(self):
        type_name = self.icmp_type.name if self.icmp_type in ICMPType._value2member_map_ else str(self.icmp_type)
        self.fields = {
            "type": f"{type_name} ({int(self.icmp_type)})",
            "code": self.code,
            "checksum": f"0x{self.checksum:04x}",
            "identifier": self.identifier,
            "sequence": self.sequence_number,
        }

    @property
    def name(self) -> str:
        return "ICMP"

    @property
    def header_length(self) -> int:
        return 8

    def pack(self, payload: bytes = b"") -> bytes:
        """Serialize ICMP header and calculate checksum covering header + payload."""
        buf = PacketBuffer()
        buf.write_uint8(int(self.icmp_type))
        buf.write_uint8(self.code)
        buf.write_uint16_be(0)  # zero checksum for calculation

        if self.icmp_type in (ICMPType.ECHO_REQUEST, ICMPType.ECHO_REPLY):
            buf.write_uint16_be(self.identifier)
            buf.write_uint16_be(self.sequence_number)
        else:
            buf.write_uint32_be(self.rest_of_header)

        header_bytes = buf.to_bytes()
        calculated_csum = calculate_internet_checksum(header_bytes + payload)
        self.checksum = calculated_csum
        self._sync_fields()

        # Re-pack with real checksum
        buf.overwrite_at(2, struct.pack("!H", calculated_csum))
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> ICMPHeader:
        if buffer.remaining < 8:
            raise DissectionError("Buffer underflow unpacking ICMPHeader")
        type_val = buffer.read_uint8()
        code = buffer.read_uint8()
        checksum = buffer.read_uint16_be()
        icmp_type = ICMPType(type_val) if type_val in ICMPType._value2member_map_ else ICMPType.ECHO_REQUEST

        if icmp_type in (ICMPType.ECHO_REQUEST, ICMPType.ECHO_REPLY):
            ident = buffer.read_uint16_be()
            seq = buffer.read_uint16_be()
            rest = 0
        else:
            rest = buffer.read_uint32_be()
            ident, seq = 0, 0

        hdr = cls(icmp_type=icmp_type, code=code, identifier=ident, sequence_number=seq, rest_of_header=rest)
        hdr.checksum = checksum
        hdr._sync_fields()
        return hdr


ProtocolRegistry.register_ip_protocol(TransportProtocol.ICMP, ICMPHeader)
'''
    total_lines += write_code_file("netsphere/protocols/l3/icmp.py", content_icmp)

    # netsphere/protocols/l3/icmpv6.py
    content_icmpv6 = '''"""
Internet Control Message Protocol for IPv6 (ICMPv6 - RFC 4443 & RFC 4861 Neighbor Discovery).
"""
from __future__ import annotations
import enum
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import TransportProtocol
from netsphere.core.checksum import calculate_internet_checksum
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class ICMPv6Type(enum.IntEnum):
    DESTINATION_UNREACHABLE = 1
    PACKET_TOO_BIG = 2
    TIME_EXCEEDED = 3
    PARAMETER_PROBLEM = 4
    ECHO_REQUEST = 128
    ECHO_REPLY = 129
    ROUTER_SOLICITATION = 133
    ROUTER_ADVERTISEMENT = 134
    NEIGHBOR_SOLICITATION = 135
    NEIGHBOR_ADVERTISEMENT = 136
    REDIRECT_MESSAGE = 137


class ICMPv6Header(ProtocolHeader):
    """
    ICMPv6 Header (RFC 4443):
    - Type (1 byte)
    - Code (1 byte)
    - Checksum (2 bytes)
    - Message Body (variable, default 4 bytes ID + Seq)
    """
    def __init__(
        self,
        msg_type: ICMPv6Type = ICMPv6Type.ECHO_REQUEST,
        code: int = 0,
        identifier: int = 0,
        sequence_number: int = 0,
    ):
        super().__init__()
        self.msg_type = msg_type
        self.code = code
        self.checksum = 0
        self.identifier = identifier
        self.sequence_number = sequence_number
        self.fields = {
            "type": f"{self.msg_type.name} ({int(self.msg_type)})",
            "code": self.code,
            "identifier": self.identifier,
            "sequence": self.sequence_number,
        }

    @property
    def name(self) -> str:
        return "ICMPv6"

    @property
    def header_length(self) -> int:
        return 8

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(int(self.msg_type))
        buf.write_uint8(self.code)
        buf.write_uint16_be(self.checksum)
        buf.write_uint16_be(self.identifier)
        buf.write_uint16_be(self.sequence_number)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> ICMPv6Header:
        if buffer.remaining < 8:
            raise DissectionError("Buffer underflow unpacking ICMPv6")
        t = buffer.read_uint8()
        c = buffer.read_uint8()
        csum = buffer.read_uint16_be()
        ident = buffer.read_uint16_be()
        seq = buffer.read_uint16_be()
        msg_t = ICMPv6Type(t) if t in ICMPv6Type._value2member_map_ else ICMPv6Type.ECHO_REQUEST
        hdr = cls(msg_type=msg_t, code=c, identifier=ident, sequence_number=seq)
        hdr.checksum = csum
        return hdr


ProtocolRegistry.register_ip_protocol(TransportProtocol.IPV6_ICMP, ICMPv6Header)
'''
    total_lines += write_code_file("netsphere/protocols/l3/icmpv6.py", content_icmpv6)

    # netsphere/protocols/l3/igmp.py
    content_igmp = '''"""
Internet Group Management Protocol (IGMPv1/v2/v3 - RFC 1112 / RFC 2236 / RFC 3376).
"""
from __future__ import annotations
import enum
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address, TransportProtocol
from netsphere.core.checksum import calculate_internet_checksum
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class IGMPType(enum.IntEnum):
    MEMBERSHIP_QUERY = 0x11
    V1_MEMBERSHIP_REPORT = 0x12
    V2_MEMBERSHIP_REPORT = 0x16
    V2_LEAVE_GROUP = 0x17
    V3_MEMBERSHIP_REPORT = 0x22


class IGMPHeader(ProtocolHeader):
    """
    IGMPv2 Header (8 bytes):
    - Type (1 byte)
    - Max Response Time (1 byte, 1/10 sec units)
    - Checksum (2 bytes)
    - Group Address (4 bytes)
    """
    def __init__(
        self,
        igmp_type: IGMPType = IGMPType.V2_MEMBERSHIP_REPORT,
        max_resp_time: int = 100,
        group_address: IPv4Address = IPv4Address("224.0.0.1"),
    ):
        super().__init__()
        self.igmp_type = igmp_type
        self.max_resp_time = max_resp_time
        self.checksum = 0
        self.group_address = group_address
        self.fields = {
            "type": self.igmp_type.name,
            "max_resp_time_sec": self.max_resp_time / 10.0,
            "group_address": str(self.group_address),
        }

    @property
    def name(self) -> str:
        return "IGMP"

    @property
    def header_length(self) -> int:
        return 8

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(int(self.igmp_type))
        buf.write_uint8(self.max_resp_time)
        buf.write_uint16_be(0)
        buf.write_bytes(self.group_address.packed)
        raw = buf.to_bytes()
        csum = calculate_internet_checksum(raw)
        self.checksum = csum
        buf.overwrite_at(2, struct.pack("!H", csum))
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> IGMPHeader:
        if buffer.remaining < 8:
            raise DissectionError("Buffer underflow unpacking IGMP")
        t = buffer.read_uint8()
        resp = buffer.read_uint8()
        csum = buffer.read_uint16_be()
        grp = IPv4Address(buffer.read_bytes(4))
        igmp_t = IGMPType(t) if t in IGMPType._value2member_map_ else IGMPType.V2_MEMBERSHIP_REPORT
        hdr = cls(igmp_type=igmp_t, max_resp_time=resp, group_address=grp)
        hdr.checksum = csum
        return hdr


import struct
ProtocolRegistry.register_ip_protocol(TransportProtocol.IGMP, IGMPHeader)
'''
    total_lines += write_code_file("netsphere/protocols/l3/igmp.py", content_igmp)

    # netsphere/protocols/l3/ipsec.py
    content_ipsec = '''"""
IP Security Architecture (IPsec): AH (RFC 4302) and ESP (RFC 4303).
"""
from __future__ import annotations
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import TransportProtocol
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class AHHeader(ProtocolHeader):
    """
    IPsec Authentication Header (RFC 4302):
    - Next Header (1 byte)
    - Payload Length (1 byte)
    - Reserved (2 bytes)
    - Security Parameters Index (SPI) (4 bytes)
    - Sequence Number (4 bytes)
    - Integrity Check Value (ICV) (variable, multiple of 32 bits)
    """
    def __init__(self, next_header: int = TransportProtocol.TCP, spi: int = 0x1000, sequence_number: int = 1, icv: bytes = b"\\x00"*12):
        super().__init__()
        self.next_header = next_header
        self.spi = spi
        self.sequence_number = sequence_number
        self.icv = icv
        self.payload_len = (12 + len(icv)) // 4 - 2
        self.fields = {"next_header": next_header, "spi": f"0x{spi:08x}", "seq": sequence_number, "icv_len": len(icv)}

    @property
    def name(self) -> str:
        return "IPsec-AH"

    @property
    def header_length(self) -> int:
        return (self.payload_len + 2) * 4

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(self.next_header)
        buf.write_uint8(self.payload_len)
        buf.write_uint16_be(0)
        buf.write_uint32_be(self.spi)
        buf.write_uint32_be(self.sequence_number)
        buf.write_bytes(self.icv)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> AHHeader:
        if buffer.remaining < 12:
            raise DissectionError("Buffer underflow unpacking AHHeader")
        nxt = buffer.read_uint8()
        plen = buffer.read_uint8()
        _res = buffer.read_uint16_be()
        spi = buffer.read_uint32_be()
        seq = buffer.read_uint32_be()
        total_len = (plen + 2) * 4
        icv_len = total_len - 12
        if buffer.remaining < icv_len:
            raise DissectionError("Buffer underflow unpacking AH ICV")
        icv = buffer.read_bytes(icv_len)
        return cls(next_header=nxt, spi=spi, sequence_number=seq, icv=icv)


class ESPHeader(ProtocolHeader):
    """
    IPsec Encapsulating Security Payload (RFC 4303):
    - Security Parameters Index (SPI) (4 bytes)
    - Sequence Number (4 bytes)
    - Payload Data (variable, encrypted)
    """
    def __init__(self, spi: int = 0x2000, sequence_number: int = 1):
        super().__init__()
        self.spi = spi
        self.sequence_number = sequence_number
        self.fields = {"spi": f"0x{spi:08x}", "seq": sequence_number}

    @property
    def name(self) -> str:
        return "IPsec-ESP"

    @property
    def header_length(self) -> int:
        return 8

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint32_be(self.spi)
        buf.write_uint32_be(self.sequence_number)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> ESPHeader:
        if buffer.remaining < 8:
            raise DissectionError("Buffer underflow unpacking ESPHeader")
        spi = buffer.read_uint32_be()
        seq = buffer.read_uint32_be()
        return cls(spi=spi, sequence_number=seq)


ProtocolRegistry.register_ip_protocol(TransportProtocol.AH, AHHeader)
ProtocolRegistry.register_ip_protocol(TransportProtocol.ESP, ESPHeader)
'''
    total_lines += write_code_file("netsphere/protocols/l3/ipsec.py", content_ipsec)

    # netsphere/protocols/l3/gre.py
    content_gre = '''"""
Generic Routing Encapsulation (GRE - RFC 1701 / RFC 2784).
"""
from __future__ import annotations
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import TransportProtocol, EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class GREHeader(ProtocolHeader):
    """
    Standard GRE Header (RFC 2784):
    - Flags: Checksum Present (1 bit), Reserved (12 bits), Version (3 bits)
    - Protocol Type: EtherType of encapsulated payload (2 bytes)
    - Optional Checksum (2 bytes) + Reserved (2 bytes)
    - Optional Key (4 bytes)
    - Optional Sequence Number (4 bytes)
    """
    def __init__(
        self,
        protocol_type: int = EtherType.IPV4,
        checksum_present: bool = False,
        key_present: bool = False,
        sequence_present: bool = False,
        key: int = 0,
        sequence_number: int = 0,
    ):
        super().__init__()
        self.checksum_present = checksum_present
        self.key_present = key_present
        self.sequence_present = sequence_present
        self.version = 0
        self.protocol_type = protocol_type
        self.key = key
        self.sequence_number = sequence_number
        self.fields = {
            "protocol_type": f"0x{protocol_type:04x}",
            "checksum_present": checksum_present,
            "key_present": key_present,
            "sequence_present": sequence_present,
            "key": key if key_present else None,
            "sequence_number": sequence_number if sequence_present else None,
        }

    @property
    def name(self) -> str:
        return "GRE"

    @property
    def header_length(self) -> int:
        length = 4
        if self.checksum_present:
            length += 4
        if self.key_present:
            length += 4
        if self.sequence_present:
            length += 4
        return length

    def pack(self) -> bytes:
        buf = PacketBuffer()
        flags = (1 if self.checksum_present else 0) << 15
        flags |= (1 if self.key_present else 0) << 13
        flags |= (1 if self.sequence_present else 0) << 12
        flags |= (self.version & 0x07)
        buf.write_uint16_be(flags)
        buf.write_uint16_be(self.protocol_type)

        if self.checksum_present:
            buf.write_uint16_be(0)  # Checksum
            buf.write_uint16_be(0)  # Reserved1
        if self.key_present:
            buf.write_uint32_be(self.key)
        if self.sequence_present:
            buf.write_uint32_be(self.sequence_number)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> GREHeader:
        if buffer.remaining < 4:
            raise DissectionError("Buffer underflow unpacking GREHeader")
        flags = buffer.read_uint16_be()
        csum_present = bool(flags & 0x8000)
        key_present = bool(flags & 0x2000)
        seq_present = bool(flags & 0x1000)
        proto = buffer.read_uint16_be()

        if csum_present:
            buffer.read_uint32_be()  # Checksum + Reserved
        key = buffer.read_uint32_be() if key_present else 0
        seq = buffer.read_uint32_be() if seq_present else 0

        return cls(
            protocol_type=proto,
            checksum_present=csum_present,
            key_present=key_present,
            sequence_present=seq_present,
            key=key,
            sequence_number=seq,
        )


ProtocolRegistry.register_ip_protocol(TransportProtocol.GRE, GREHeader)
'''
    total_lines += write_code_file("netsphere/protocols/l3/gre.py", content_gre)

    print(f"[*] Completed Protocols L2 & L3 generation: {total_lines:,} LOC")
    return total_lines

if __name__ == "__main__":
    generate_protocols_l2_l3()
