"""
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
