"""
IP Security Architecture (IPsec): AH (RFC 4302) and ESP (RFC 4303).
"""
from __future__ import annotations
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import TransportProtocol
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class AHHeader(ProtocolHeader):
    """
    IPsec Authentication Header (RFC 4302):
    - Next Header (1 byte)
    - Payload Length (1 byte)
    - Reserved (2 bytes)
    - Security Parameters Index (SPI) (4 bytes)
    - Sequence Number (4 bytes)
    - Integrity Check Value (ICV) (variable, multiple of 32 bits)
    """
    def __init__(self, next_header: int = TransportProtocol.TCP, spi: int = 0x1000, sequence_number: int = 1, icv: bytes = b"\x00"*12):
        super().__init__()
        self.next_header = next_header
        self.spi = spi
        self.sequence_number = sequence_number
        self.icv = icv
        self.payload_len = (12 + len(icv)) // 4 - 2
        self.fields = {"next_header": next_header, "spi": f"0x{spi:08x}", "seq": sequence_number, "icv_len": len(icv)}

    @property
    def name(self) -> str:
        return "IPsec-AH"

    @property
    def header_length(self) -> int:
        return (self.payload_len + 2) * 4

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(self.next_header)
        buf.write_uint8(self.payload_len)
        buf.write_uint16_be(0)
        buf.write_uint32_be(self.spi)
        buf.write_uint32_be(self.sequence_number)
        buf.write_bytes(self.icv)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> AHHeader:
        if buffer.remaining < 12:
            raise DissectionError("Buffer underflow unpacking AHHeader")
        nxt = buffer.read_uint8()
        plen = buffer.read_uint8()
        _res = buffer.read_uint16_be()
        spi = buffer.read_uint32_be()
        seq = buffer.read_uint32_be()
        total_len = (plen + 2) * 4
        icv_len = total_len - 12
        if buffer.remaining < icv_len:
            raise DissectionError("Buffer underflow unpacking AH ICV")
        icv = buffer.read_bytes(icv_len)
        return cls(next_header=nxt, spi=spi, sequence_number=seq, icv=icv)


class ESPHeader(ProtocolHeader):
    """
    IPsec Encapsulating Security Payload (RFC 4303):
    - Security Parameters Index (SPI) (4 bytes)
    - Sequence Number (4 bytes)
    - Payload Data (variable, encrypted)
    """
    def __init__(self, spi: int = 0x2000, sequence_number: int = 1):
        super().__init__()
        self.spi = spi
        self.sequence_number = sequence_number
        self.fields = {"spi": f"0x{spi:08x}", "seq": sequence_number}

    @property
    def name(self) -> str:
        return "IPsec-ESP"

    @property
    def header_length(self) -> int:
        return 8

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint32_be(self.spi)
        buf.write_uint32_be(self.sequence_number)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> ESPHeader:
        if buffer.remaining < 8:
            raise DissectionError("Buffer underflow unpacking ESPHeader")
        spi = buffer.read_uint32_be()
        seq = buffer.read_uint32_be()
        return cls(spi=spi, sequence_number=seq)


ProtocolRegistry.register_ip_protocol(TransportProtocol.AH, AHHeader)
ProtocolRegistry.register_ip_protocol(TransportProtocol.ESP, ESPHeader)
