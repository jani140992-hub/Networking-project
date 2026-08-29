"""
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
