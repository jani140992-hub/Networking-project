"""
Open Shortest Path First Version 2 (OSPFv2 - RFC 2328).
"""
from __future__ import annotations
import enum
import struct
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address
from netsphere.core.checksum import calculate_internet_checksum
from netsphere.protocols.base import DissectionError


class OSPFType(enum.IntEnum):
    HELLO = 1
    DATABASE_DESCRIPTION = 2
    LINK_STATE_REQUEST = 3
    LINK_STATE_UPDATE = 4
    LINK_STATE_ACK = 5


class OSPFMessage:
    """
    OSPF Header (24 bytes):
    - Version: 2 (1 byte)
    - Type: 1 byte
    - Packet Length: 2 bytes
    - Router ID: 4 bytes
    - Area ID: 4 bytes
    - Checksum: 2 bytes
    - AuType: 2 bytes
    - Authentication: 8 bytes
    Followed by OSPF payload.
    """
    def __init__(
        self,
        ospf_type: OSPFType = OSPFType.HELLO,
        router_id: IPv4Address = IPv4Address("10.0.0.1"),
        area_id: IPv4Address = IPv4Address("0.0.0.0"),
        payload: bytes = b"",
    ):
        self.version = 2
        self.ospf_type = ospf_type
        self.router_id = router_id
        self.area_id = area_id
        self.checksum = 0
        self.autype = 0
        self.payload = payload

    @property
    def length(self) -> int:
        return 24 + len(self.payload)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(self.version)
        buf.write_uint8(int(self.ospf_type))
        buf.write_uint16_be(self.length)
        buf.write_bytes(self.router_id.packed)
        buf.write_bytes(self.area_id.packed)
        buf.write_uint16_be(0)  # Checksum placeholder
        buf.write_uint16_be(self.autype)
        buf.write_bytes(b"\x00" * 8)
        buf.write_bytes(self.payload)

        raw = buf.to_bytes()
        csum = calculate_internet_checksum(raw[:24] + self.payload)
        self.checksum = csum
        buf.overwrite_at(12, struct.pack("!H", csum))
        return buf.to_bytes()
