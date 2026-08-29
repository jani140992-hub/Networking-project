"""
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
