"""
Border Gateway Protocol Version 4 (BGP-4 - RFC 4271).
"""
from __future__ import annotations
import enum
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address
from netsphere.protocols.base import DissectionError


class BGPType(enum.IntEnum):
    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4
    ROUTE_REFRESH = 5


class BGPMessage:
    """
    BGP Header (19 bytes):
    - Marker: 16 bytes (all 1s, \xff*16)
    - Length: 2 bytes
    - Type: 1 byte
    Followed by Message Body.
    """
    MARKER = b"\xff" * 16

    def __init__(self, bgp_type: BGPType = BGPType.KEEPALIVE, body: bytes = b""):
        self.bgp_type = bgp_type
        self.body = body

    @property
    def length(self) -> int:
        return 19 + len(self.body)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_bytes(self.MARKER)
        buf.write_uint16_be(self.length)
        buf.write_uint8(int(self.bgp_type))
        buf.write_bytes(self.body)
        return buf.to_bytes()

    @classmethod
    def open(cls, my_as: int = 65001, hold_time: int = 180, bgp_id: str = "192.168.1.1") -> BGPMessage:
        buf = PacketBuffer()
        buf.write_uint8(4) # Version 4
        buf.write_uint16_be(my_as)
        buf.write_uint16_be(hold_time)
        buf.write_bytes(IPv4Address(bgp_id).packed)
        buf.write_uint8(0) # Opt Parm Length
        return cls(BGPType.OPEN, buf.to_bytes())

    @classmethod
    def keepalive(cls) -> BGPMessage:
        return cls(BGPType.KEEPALIVE)

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> BGPMessage:
        if buffer.remaining < 19:
            raise DissectionError("Buffer underflow unpacking BGP message")
        marker = buffer.read_bytes(16)
        length = buffer.read_uint16_be()
        m_type = buffer.read_uint8()
        body_len = length - 19
        body = buffer.read_bytes(body_len) if body_len > 0 else b""
        bgp_t = BGPType(m_type) if m_type in BGPType._value2member_map_ else BGPType.KEEPALIVE
        return cls(bgp_type=bgp_t, body=body)
