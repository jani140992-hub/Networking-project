"""
Generic Routing Encapsulation (GRE - RFC 1701 / RFC 2784).
"""
from __future__ import annotations
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import TransportProtocol, EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class GREHeader(ProtocolHeader):
    """
    Standard GRE Header (RFC 2784):
    - Flags: Checksum Present (1 bit), Reserved (12 bits), Version (3 bits)
    - Protocol Type: EtherType of encapsulated payload (2 bytes)
    - Optional Checksum (2 bytes) + Reserved (2 bytes)
    - Optional Key (4 bytes)
    - Optional Sequence Number (4 bytes)
    """
    def __init__(
        self,
        protocol_type: int = EtherType.IPV4,
        checksum_present: bool = False,
        key_present: bool = False,
        sequence_present: bool = False,
        key: int = 0,
        sequence_number: int = 0,
    ):
        super().__init__()
        self.checksum_present = checksum_present
        self.key_present = key_present
        self.sequence_present = sequence_present
        self.version = 0
        self.protocol_type = protocol_type
        self.key = key
        self.sequence_number = sequence_number
        self.fields = {
            "protocol_type": f"0x{protocol_type:04x}",
            "checksum_present": checksum_present,
            "key_present": key_present,
            "sequence_present": sequence_present,
            "key": key if key_present else None,
            "sequence_number": sequence_number if sequence_present else None,
        }

    @property
    def name(self) -> str:
        return "GRE"

    @property
    def header_length(self) -> int:
        length = 4
        if self.checksum_present:
            length += 4
        if self.key_present:
            length += 4
        if self.sequence_present:
            length += 4
        return length

    def pack(self) -> bytes:
        buf = PacketBuffer()
        flags = (1 if self.checksum_present else 0) << 15
        flags |= (1 if self.key_present else 0) << 13
        flags |= (1 if self.sequence_present else 0) << 12
        flags |= (self.version & 0x07)
        buf.write_uint16_be(flags)
        buf.write_uint16_be(self.protocol_type)

        if self.checksum_present:
            buf.write_uint16_be(0)  # Checksum
            buf.write_uint16_be(0)  # Reserved1
        if self.key_present:
            buf.write_uint32_be(self.key)
        if self.sequence_present:
            buf.write_uint32_be(self.sequence_number)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> GREHeader:
        if buffer.remaining < 4:
            raise DissectionError("Buffer underflow unpacking GREHeader")
        flags = buffer.read_uint16_be()
        csum_present = bool(flags & 0x8000)
        key_present = bool(flags & 0x2000)
        seq_present = bool(flags & 0x1000)
        proto = buffer.read_uint16_be()

        if csum_present:
            buffer.read_uint32_be()  # Checksum + Reserved
        key = buffer.read_uint32_be() if key_present else 0
        seq = buffer.read_uint32_be() if seq_present else 0

        return cls(
            protocol_type=proto,
            checksum_present=csum_present,
            key_present=key_present,
            sequence_present=seq_present,
            key=key,
            sequence_number=seq,
        )


ProtocolRegistry.register_ip_protocol(TransportProtocol.GRE, GREHeader)
