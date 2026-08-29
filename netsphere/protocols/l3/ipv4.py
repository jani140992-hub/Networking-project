"""
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
                buf.write_bytes(b"\x00" * pad_len)
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
