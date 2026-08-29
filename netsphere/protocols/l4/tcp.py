"""
Transmission Control Protocol (TCP - RFC 793 / RFC 7323 / RFC 2018).
"""
from __future__ import annotations
import enum
import struct
from dataclasses import dataclass
from typing import Optional, List, Tuple
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import Port, TransportProtocol
from netsphere.core.checksum import compute_pseudo_header_checksum
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


@dataclass
class TCPFlags:
    fin: bool = False
    syn: bool = False
    rst: bool = False
    psh: bool = False
    ack: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False
    ns: bool = False

    def to_int(self) -> int:
        val = 0
        if self.fin: val |= 0x001
        if self.syn: val |= 0x002
        if self.rst: val |= 0x004
        if self.psh: val |= 0x008
        if self.ack: val |= 0x010
        if self.urg: val |= 0x020
        if self.ece: val |= 0x040
        if self.cwr: val |= 0x080
        if self.ns:  val |= 0x100
        return val

    @classmethod
    def from_int(cls, val: int) -> TCPFlags:
        return cls(
            fin=bool(val & 0x001),
            syn=bool(val & 0x002),
            rst=bool(val & 0x004),
            psh=bool(val & 0x008),
            ack=bool(val & 0x010),
            urg=bool(val & 0x020),
            ece=bool(val & 0x040),
            cwr=bool(val & 0x080),
            ns=bool(val & 0x100),
        )

    def __str__(self) -> str:
        flags = []
        if self.syn: flags.append("SYN")
        if self.ack: flags.append("ACK")
        if self.fin: flags.append("FIN")
        if self.rst: flags.append("RST")
        if self.psh: flags.append("PSH")
        if self.urg: flags.append("URG")
        if self.ece: flags.append("ECE")
        if self.cwr: flags.append("CWR")
        return "[" + ",".join(flags) + "]" if flags else "[NONE]"


class TCPOptionKind(enum.IntEnum):
    END_OF_OPTION_LIST = 0
    NO_OPERATION = 1
    MAXIMUM_SEGMENT_SIZE = 2
    WINDOW_SCALE = 3
    SACK_PERMITTED = 4
    SACK = 5
    TIMESTAMPS = 8


class TCPOption:
    """Represents a TCP Option field."""
    def __init__(self, kind: int, data: bytes = b""):
        self.kind = kind
        self.data = data

    @property
    def length(self) -> int:
        if self.kind in (0, 1):
            return 1
        return 2 + len(self.data)

    def pack(self) -> bytes:
        if self.kind in (0, 1):
            return bytes([self.kind])
        return bytes([self.kind, 2 + len(self.data)]) + self.data

    @classmethod
    def mss(cls, size: int) -> TCPOption:
        return cls(TCPOptionKind.MAXIMUM_SEGMENT_SIZE, struct.pack("!H", size))

    @classmethod
    def window_scale(cls, shift: int) -> TCPOption:
        return cls(TCPOptionKind.WINDOW_SCALE, bytes([shift]))

    @classmethod
    def sack_permitted(cls) -> TCPOption:
        return cls(TCPOptionKind.SACK_PERMITTED)

    @classmethod
    def timestamps(cls, tsval: int, tsecr: int) -> TCPOption:
        return cls(TCPOptionKind.TIMESTAMPS, struct.pack("!II", tsval, tsecr))


class TCPHeader(ProtocolHeader):
    """
    TCP Header (20 bytes standard, up to 60 bytes with options):
    - Source Port (16 bits)
    - Destination Port (16 bits)
    - Sequence Number (32 bits)
    - Acknowledgment Number (32 bits)
    - Data Offset (4 bits) + Reserved (3 bits) + NS flag (1 bit)
    - Flags: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN (8 bits)
    - Window Size (16 bits)
    - Checksum (16 bits)
    - Urgent Pointer (16 bits)
    - Options (0-40 bytes, padded to 32-bit boundary)
    """
    def __init__(
        self,
        src_port: Port = Port(12345),
        dst_port: Port = Port(80),
        seq_num: int = 1000,
        ack_num: int = 0,
        flags: Optional[TCPFlags] = None,
        window_size: int = 65535,
        urgent_pointer: int = 0,
        options: Optional[List[TCPOption]] = None,
    ):
        super().__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags or TCPFlags(syn=True)
        self.window_size = window_size
        self.checksum = 0
        self.urgent_pointer = urgent_pointer
        self.options = options or []
        self._sync_fields()

    @property
    def data_offset(self) -> int:
        opt_len = sum(opt.length for opt in self.options)
        pad_len = (4 - (opt_len % 4)) % 4
        return 5 + (opt_len + pad_len) // 4

    def _sync_fields(self):
        self.fields = {
            "src_port": int(self.src_port),
            "dst_port": int(self.dst_port),
            "seq_num": self.seq_num,
            "ack_num": self.ack_num,
            "flags": str(self.flags),
            "window_size": self.window_size,
            "checksum": f"0x{self.checksum:04x}",
            "options_count": len(self.options),
        }

    @property
    def name(self) -> str:
        return "TCP"

    @property
    def header_length(self) -> int:
        return self.data_offset * 4

    def pack(self, src_ip: Optional[bytes] = None, dst_ip: Optional[bytes] = None, payload: bytes = b"") -> bytes:
        buf = PacketBuffer()
        buf.write_uint16_be(int(self.src_port))
        buf.write_uint16_be(int(self.dst_port))
        buf.write_uint32_be(self.seq_num)
        buf.write_uint32_be(self.ack_num)

        offset_flags = (self.data_offset << 12) | (self.flags.to_int() & 0x0FFF)
        buf.write_uint16_be(offset_flags)
        buf.write_uint16_be(self.window_size)
        buf.write_uint16_be(0)  # Checksum placeholder
        buf.write_uint16_be(self.urgent_pointer)

        # Options packing
        for opt in self.options:
            buf.write_bytes(opt.pack())
        opt_bytes = sum(opt.length for opt in self.options)
        padding = (4 - (opt_bytes % 4)) % 4
        if padding > 0:
            buf.write_bytes(b"\x00" * padding)

        hdr_bytes = buf.to_bytes()

        # Checksum calculation with IPv4 pseudo-header if addresses provided
        if src_ip and dst_ip:
            calculated_csum = compute_pseudo_header_checksum(
                src_ip_bytes=src_ip,
                dst_ip_bytes=dst_ip,
                protocol=TransportProtocol.TCP,
                payload_length=len(hdr_bytes) + len(payload),
                payload_bytes=hdr_bytes + payload,
            )
            self.checksum = calculated_csum
            self._sync_fields()
            buf.overwrite_at(16, struct.pack("!H", calculated_csum))

        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> TCPHeader:
        if buffer.remaining < 20:
            raise DissectionError("Buffer underflow unpacking TCPHeader")
        src_port = Port(buffer.read_uint16_be())
        dst_port = Port(buffer.read_uint16_be())
        seq = buffer.read_uint32_be()
        ack = buffer.read_uint32_be()
        offset_flags = buffer.read_uint16_be()
        data_offset = (offset_flags >> 12) & 0x0F
        flags = TCPFlags.from_int(offset_flags & 0x0FFF)
        window = buffer.read_uint16_be()
        checksum = buffer.read_uint16_be()
        urg_ptr = buffer.read_uint16_be()

        options: List[TCPOption] = []
        options_len = (data_offset * 4) - 20
        if options_len > 0:
            if buffer.remaining < options_len:
                raise DissectionError("Buffer underflow reading TCP options")
            opt_buf = PacketBuffer(buffer.read_bytes(options_len))
            while opt_buf.remaining > 0:
                kind = opt_buf.read_uint8()
                if kind == TCPOptionKind.END_OF_OPTION_LIST:
                    break
                elif kind == TCPOptionKind.NO_OPERATION:
                    options.append(TCPOption(kind))
                else:
                    if opt_buf.remaining < 1:
                        break
                    length = opt_buf.read_uint8()
                    data_len = length - 2
                    if opt_buf.remaining < data_len:
                        break
                    data = opt_buf.read_bytes(data_len)
                    options.append(TCPOption(kind, data))

        hdr = cls(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq,
            ack_num=ack,
            flags=flags,
            window_size=window,
            urgent_pointer=urg_ptr,
            options=options,
        )
        hdr.checksum = checksum
        hdr._sync_fields()
        return hdr


ProtocolRegistry.register_ip_protocol(TransportProtocol.TCP, TCPHeader)
