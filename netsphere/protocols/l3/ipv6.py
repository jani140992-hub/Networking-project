"""
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
            buf.write_bytes(b"\x00" * pad)
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
