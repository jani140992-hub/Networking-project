"""
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
