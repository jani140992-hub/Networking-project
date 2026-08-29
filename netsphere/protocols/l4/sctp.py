"""
Stream Control Transmission Protocol (SCTP - RFC 4960).
"""
from __future__ import annotations
import enum
import struct
from typing import List, Optional
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import Port, TransportProtocol
from netsphere.core.checksum import calculate_crc32
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class SCTPChunkType(enum.IntEnum):
    DATA = 0
    INIT = 1
    INIT_ACK = 2
    SACK = 3
    HEARTBEAT = 4
    HEARTBEAT_ACK = 5
    ABORT = 6
    SHUTDOWN = 7
    SHUTDOWN_ACK = 8
    ERROR = 9
    COOKIE_ECHO = 10
    COOKIE_ACK = 11
    SHUTDOWN_COMPLETE = 14


class SCTPChunk:
    """SCTP Chunk (Type 1 byte, Flags 1 byte, Length 2 bytes, Value variable)."""
    def __init__(self, chunk_type: SCTPChunkType, flags: int = 0, data: bytes = b""):
        self.chunk_type = chunk_type
        self.flags = flags
        self.data = data

    @property
    def length(self) -> int:
        return 4 + len(self.data)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(int(self.chunk_type))
        buf.write_uint8(self.flags)
        buf.write_uint16_be(self.length)
        buf.write_bytes(self.data)
        # Pad to 4-byte boundary
        pad = (4 - (len(self.data) % 4)) % 4
        if pad > 0:
            buf.write_bytes(b"\x00" * pad)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> SCTPChunk:
        if buffer.remaining < 4:
            raise DissectionError("Buffer underflow unpacking SCTP chunk")
        c_type = buffer.read_uint8()
        flags = buffer.read_uint8()
        length = buffer.read_uint16_be()
        data_len = length - 4
        if buffer.remaining < data_len:
            raise DissectionError("Buffer underflow unpacking SCTP chunk data")
        data = buffer.read_bytes(data_len)
        # Read padding
        pad = (4 - (data_len % 4)) % 4
        if buffer.remaining >= pad:
            buffer.read_bytes(pad)
        chunk_t = SCTPChunkType(c_type) if c_type in SCTPChunkType._value2member_map_ else SCTPChunkType.DATA
        return cls(chunk_type=chunk_t, flags=flags, data=data)


class SCTPHeader(ProtocolHeader):
    """
    SCTP Common Header (12 bytes):
    - Source Port (16 bits)
    - Destination Port (16 bits)
    - Verification Tag (32 bits)
    - Checksum (32 bits - CRC32c)
    Followed by one or more Chunks.
    """
    def __init__(
        self,
        src_port: Port = Port(2905),
        dst_port: Port = Port(2905),
        verification_tag: int = 0,
        chunks: Optional[List[SCTPChunk]] = None,
    ):
        super().__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.verification_tag = verification_tag
        self.checksum = 0
        self.chunks = chunks or []
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "src_port": int(self.src_port),
            "dst_port": int(self.dst_port),
            "verification_tag": f"0x{self.verification_tag:08x}",
            "checksum": f"0x{self.checksum:08x}",
            "chunks_count": len(self.chunks),
        }

    @property
    def name(self) -> str:
        return "SCTP"

    @property
    def header_length(self) -> int:
        return 12 + sum(c.length for c in self.chunks)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint16_be(int(self.src_port))
        buf.write_uint16_be(int(self.dst_port))
        buf.write_uint32_be(self.verification_tag)
        buf.write_uint32_be(0)  # Checksum placeholder

        for chunk in self.chunks:
            buf.write_bytes(chunk.pack())

        raw = buf.to_bytes()
        csum = calculate_crc32(raw)
        self.checksum = csum
        self._sync_fields()
        buf.overwrite_at(8, struct.pack("<I", csum))
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> SCTPHeader:
        if buffer.remaining < 12:
            raise DissectionError("Buffer underflow unpacking SCTPHeader")
        src_port = Port(buffer.read_uint16_be())
        dst_port = Port(buffer.read_uint16_be())
        v_tag = buffer.read_uint32_be()
        checksum = buffer.read_uint32_be()

        chunks = []
        while buffer.remaining >= 4:
            chunk = SCTPChunk.unpack(buffer)
            chunks.append(chunk)

        hdr = cls(src_port=src_port, dst_port=dst_port, verification_tag=v_tag, chunks=chunks)
        hdr.checksum = checksum
        hdr._sync_fields()
        return hdr


ProtocolRegistry.register_ip_protocol(TransportProtocol.SCTP, SCTPHeader)
