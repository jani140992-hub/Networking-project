"""
User Datagram Protocol (UDP - RFC 768).
"""
from __future__ import annotations
import struct
from typing import Optional
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import Port, TransportProtocol
from netsphere.core.checksum import compute_pseudo_header_checksum
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class UDPHeader(ProtocolHeader):
    """
    UDP Header (8 bytes):
    - Source Port (16 bits)
    - Destination Port (16 bits)
    - Length (16 bits, header + data)
    - Checksum (16 bits, optional in IPv4, mandatory in IPv6)
    """
    def __init__(
        self,
        src_port: Port = Port(5353),
        dst_port: Port = Port(53),
        length: int = 8,
        checksum: int = 0,
    ):
        super().__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.checksum = checksum
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "src_port": int(self.src_port),
            "dst_port": int(self.dst_port),
            "length": self.length,
            "checksum": f"0x{self.checksum:04x}",
        }

    @property
    def name(self) -> str:
        return "UDP"

    @property
    def header_length(self) -> int:
        return 8

    def pack(self, src_ip: Optional[bytes] = None, dst_ip: Optional[bytes] = None, payload: bytes = b"") -> bytes:
        total_len = 8 + len(payload)
        self.length = total_len
        buf = PacketBuffer()
        buf.write_uint16_be(int(self.src_port))
        buf.write_uint16_be(int(self.dst_port))
        buf.write_uint16_be(total_len)
        buf.write_uint16_be(0)  # zero checksum for computation

        hdr_bytes = buf.to_bytes()
        if src_ip and dst_ip:
            csum = compute_pseudo_header_checksum(
                src_ip_bytes=src_ip,
                dst_ip_bytes=dst_ip,
                protocol=TransportProtocol.UDP,
                payload_length=total_len,
                payload_bytes=hdr_bytes + payload,
            )
            # RFC 768: If calculated checksum is 0, transmit as 0xFFFF
            if csum == 0:
                csum = 0xFFFF
            self.checksum = csum
            self._sync_fields()
            buf.overwrite_at(6, struct.pack("!H", csum))

        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> UDPHeader:
        if buffer.remaining < 8:
            raise DissectionError("Buffer underflow unpacking UDPHeader")
        src_port = Port(buffer.read_uint16_be())
        dst_port = Port(buffer.read_uint16_be())
        length = buffer.read_uint16_be()
        checksum = buffer.read_uint16_be()

        hdr = cls(src_port=src_port, dst_port=dst_port, length=length, checksum=checksum)
        return hdr


class UDPDatagram:
    """Represents a complete UDP datagram with header and payload."""
    def __init__(self, header: UDPHeader, payload: bytes = b""):
        self.header = header
        self.payload = payload

    def pack(self, src_ip: Optional[bytes] = None, dst_ip: Optional[bytes] = None) -> bytes:
        hdr = self.header.pack(src_ip=src_ip, dst_ip=dst_ip, payload=self.payload)
        return hdr + self.payload


ProtocolRegistry.register_ip_protocol(TransportProtocol.UDP, UDPHeader)
