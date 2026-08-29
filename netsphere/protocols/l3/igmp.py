"""
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
