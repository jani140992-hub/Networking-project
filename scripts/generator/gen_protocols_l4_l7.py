"""
NetSphere Protocols Generator: Layer 4 (Transport) and Layer 7 (Application).
"""
from common import write_code_file

def generate_protocols_l4_l7():
    total_lines = 0
    print("[*] Generating NetSphere Protocol L4 & L7 modules...")

    # netsphere/protocols/l4/__init__.py
    content_l4_init = '''"""
OSI Layer 4 (Transport Layer) Protocol implementations.
"""
from netsphere.protocols.l4.tcp import TCPHeader, TCPOption, TCPFlags
from netsphere.protocols.l4.tcp_state import TCPConnection, TCPState, RTTTracker
from netsphere.protocols.l4.udp import UDPHeader, UDPDatagram
from netsphere.protocols.l4.sctp import SCTPHeader, SCTPChunk, SCTPChunkType

__all__ = [
    "TCPHeader",
    "TCPOption",
    "TCPFlags",
    "TCPConnection",
    "TCPState",
    "RTTTracker",
    "UDPHeader",
    "UDPDatagram",
    "SCTPHeader",
    "SCTPChunk",
    "SCTPChunkType",
]
'''
    total_lines += write_code_file("netsphere/protocols/l4/__init__.py", content_l4_init)

    # netsphere/protocols/l4/tcp.py
    content_tcp = '''"""
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
            buf.write_bytes(b"\\x00" * padding)

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
'''
    total_lines += write_code_file("netsphere/protocols/l4/tcp.py", content_tcp)

    # netsphere/protocols/l4/tcp_state.py
    content_tcp_state = '''"""
TCP Finite State Machine (RFC 793) and Round-Trip Time (RTT) Estimation (RFC 6298).
"""
from __future__ import annotations
import enum
import time
from dataclasses import dataclass
from typing import Optional, List, Dict
from netsphere.protocols.l4.tcp import TCPHeader, TCPFlags


class TCPState(enum.Enum):
    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RCVD = "SYN_RCVD"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"


class RTTTracker:
    """
    Jacobson / Karels Algorithm for RTT & Retransmission Timeout (RTO) Estimation (RFC 6298):
    SRTT = (1 - alpha) * SRTT + alpha * R' (alpha = 1/8)
    RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'| (beta = 1/4)
    RTO = SRTT + max(G, 4 * RTTVAR)
    """
    def __init__(self, initial_rto: float = 1.0, min_rto: float = 0.2, max_rto: float = 60.0):
        self.srtt: Optional[float] = None
        self.rttvar: Optional[float] = None
        self.rto: float = initial_rto
        self.min_rto = min_rto
        self.max_rto = max_rto
        self.alpha = 0.125
        self.beta = 0.25

    def update(self, measured_rtt: float) -> None:
        if self.srtt is None:
            # First measurement
            self.srtt = measured_rtt
            self.rttvar = measured_rtt / 2.0
            self.rto = self.srtt + max(0.01, 4.0 * self.rttvar)
        else:
            diff = abs(self.srtt - measured_rtt)
            self.rttvar = (1.0 - self.beta) * self.rttvar + self.beta * diff
            self.srtt = (1.0 - self.alpha) * self.srtt + self.alpha * measured_rtt
            self.rto = self.srtt + max(0.01, 4.0 * self.rttvar)

        # Clamp RTO
        self.rto = max(self.min_rto, min(self.rto, self.max_rto))

    def backoff(self) -> None:
        """Exponential backoff upon retransmission timeout."""
        self.rto = min(self.rto * 2.0, self.max_rto)


class TCPConnection:
    """
    Manages TCP connection state, sequence numbers, and transitions.
    """
    def __init__(self, local_port: int, remote_port: int, initial_seq: int = 1000):
        self.local_port = local_port
        self.remote_port = remote_port
        self.state: TCPState = TCPState.CLOSED
        self.snd_una: int = initial_seq     # Oldest unacknowledged sequence number
        self.snd_nxt: int = initial_seq     # Next sequence number to send
        self.snd_wnd: int = 65535           # Send window
        self.rcv_nxt: int = 0               # Next expected receive sequence number
        self.rcv_wnd: int = 65535           # Receive window
        self.rtt_tracker = RTTTracker()
        self.duplicate_acks: int = 0
        self.last_ack_received: int = 0

    def handle_segment(self, header: TCPHeader, payload_len: int = 0) -> Optional[TCPHeader]:
        """
        Process an incoming TCP segment according to RFC 793 state machine.
        Returns a response TCPHeader if an immediate reply is required.
        """
        # Active OPEN (SYN_SENT)
        if self.state == TCPState.SYN_SENT:
            if header.flags.syn and header.flags.ack:
                self.rcv_nxt = header.seq_num + 1
                self.snd_una = header.ack_num
                self.state = TCPState.ESTABLISHED
                # Return ACK to complete 3-way handshake
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )
            elif header.flags.syn:
                # Simultaneous open
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.SYN_RCVD
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(syn=True, ack=True),
                )

        # Passive LISTEN
        elif self.state == TCPState.LISTEN:
            if header.flags.syn:
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.SYN_RCVD
                resp = TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(syn=True, ack=True),
                )
                self.snd_nxt += 1
                return resp

        # SYN_RCVD
        elif self.state == TCPState.SYN_RCVD:
            if header.flags.ack:
                self.snd_una = header.ack_num
                self.state = TCPState.ESTABLISHED

        # ESTABLISHED
        elif self.state == TCPState.ESTABLISHED:
            if header.flags.fin:
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.CLOSE_WAIT
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )
            elif payload_len > 0:
                self.rcv_nxt = header.seq_num + payload_len
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )

        # FIN_WAIT_1
        elif self.state == TCPState.FIN_WAIT_1:
            if header.flags.fin and header.flags.ack:
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.TIME_WAIT
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )
            elif header.flags.ack:
                self.state = TCPState.FIN_WAIT_2

        # FIN_WAIT_2
        elif self.state == TCPState.FIN_WAIT_2:
            if header.flags.fin:
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.TIME_WAIT
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )

        # LAST_ACK
        elif self.state == TCPState.LAST_ACK:
            if header.flags.ack:
                self.state = TCPState.CLOSED

        return None
'''
    total_lines += write_code_file("netsphere/protocols/l4/tcp_state.py", content_tcp_state)

    # netsphere/protocols/l4/udp.py
    content_udp = '''"""
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
'''
    total_lines += write_code_file("netsphere/protocols/l4/udp.py", content_udp)

    # netsphere/protocols/l4/sctp.py
    content_sctp = '''"""
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
            buf.write_bytes(b"\\x00" * pad)
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
'''
    total_lines += write_code_file("netsphere/protocols/l4/sctp.py", content_sctp)

    # netsphere/protocols/l7/__init__.py
    content_l7_init = '''"""
OSI Layer 7 (Application Layer) Protocol implementations.
"""
from netsphere.protocols.l7.dns import DNSMessage, DNSHeader, DNSQuestion, DNSRR, DNSType
from netsphere.protocols.l7.dhcp import DHCPMessage, DHCPOption, DHCPMessageType
from netsphere.protocols.l7.http1 import HTTP1Request, HTTP1Response
from netsphere.protocols.l7.http2 import HTTP2Frame, HTTP2FrameType
from netsphere.protocols.l7.mqtt import MQTTMessage, MQTTMessageType
from netsphere.protocols.l7.coap import CoAPMessage, CoAPType, CoAPCode
from netsphere.protocols.l7.snmp import SNMPMessage, SNMPPDU, SNMPType
from netsphere.protocols.l7.bgp import BGPMessage, BGPType
from netsphere.protocols.l7.ospf import OSPFMessage, OSPFType
from netsphere.protocols.l7.ntp import NTPMessage
from netsphere.protocols.l7.syslog import SyslogMessage, SyslogFacility, SyslogSeverity
from netsphere.protocols.l7.websocket import WebSocketFrame, WebSocketOpcode

__all__ = [
    "DNSMessage",
    "DNSHeader",
    "DNSQuestion",
    "DNSRR",
    "DNSType",
    "DHCPMessage",
    "DHCPOption",
    "DHCPMessageType",
    "HTTP1Request",
    "HTTP1Response",
    "HTTP2Frame",
    "HTTP2FrameType",
    "MQTTMessage",
    "MQTTMessageType",
    "CoAPMessage",
    "CoAPType",
    "CoAPCode",
    "SNMPMessage",
    "SNMPPDU",
    "SNMPType",
    "BGPMessage",
    "BGPType",
    "OSPFMessage",
    "OSPFType",
    "NTPMessage",
    "SyslogMessage",
    "SyslogFacility",
    "SyslogSeverity",
    "WebSocketFrame",
    "WebSocketOpcode",
]
'''
    total_lines += write_code_file("netsphere/protocols/l7/__init__.py", content_l7_init)

    # netsphere/protocols/l7/dns.py
    content_dns = '''"""
Domain Name System (DNS - RFC 1035).
"""
from __future__ import annotations
import enum
import struct
from typing import List, Optional, Tuple
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address, IPv6Address
from netsphere.protocols.base import ProtocolHeader, DissectionError


class DNSType(enum.IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    ANY = 255
    CAA = 257


class DNSClass(enum.IntEnum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4
    ANY = 255


def encode_dns_name(name: str) -> bytes:
    """Encode domain name into DNS wire format (e.g. 'www.google.com' -> \\x03www\\x06google\\x03com\\x00)."""
    parts = name.strip(".").split(".")
    buf = bytearray()
    for part in parts:
        encoded = part.encode("ascii")
        buf.append(len(encoded))
        buf.extend(encoded)
    buf.append(0)
    return bytes(buf)


def decode_dns_name(buffer: PacketBuffer) -> str:
    """Decode DNS wire name handling compression pointers (RFC 1035 section 4.1.4)."""
    labels = []
    visited_offsets = set()
    orig_cursor = buffer.cursor

    while True:
        length = buffer.read_uint8()
        if length == 0:
            break
        # Pointer check (top two bits 11)
        if (length & 0xC0) == 0xC0:
            pointer_offset = ((length & 0x3F) << 8) | buffer.read_uint8()
            if pointer_offset in visited_offsets:
                raise DissectionError("DNS compression pointer loop detected")
            visited_offsets.add(pointer_offset)
            current_cursor = buffer.cursor
            buffer.cursor = pointer_offset
            sub_name = decode_dns_name(buffer)
            labels.append(sub_name)
            buffer.cursor = current_cursor
            break
        else:
            label_bytes = buffer.read_bytes(length)
            labels.append(label_bytes.decode("ascii", errors="replace"))

    return ".".join(labels)


class DNSHeader(ProtocolHeader):
    """
    DNS Header (12 bytes):
    - ID (16 bits)
    - Flags (16 bits: QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    - QDCOUNT (16 bits)
    - ANCOUNT (16 bits)
    - NSCOUNT (16 bits)
    - ARCOUNT (16 bits)
    """
    def __init__(
        self,
        transaction_id: int = 0x1A2B,
        is_response: bool = False,
        opcode: int = 0,
        authoritative: bool = False,
        truncated: bool = False,
        recursion_desired: bool = True,
        recursion_available: bool = False,
        rcode: int = 0,
        qdcount: int = 1,
        ancount: int = 0,
        nscount: int = 0,
        arcount: int = 0,
    ):
        super().__init__()
        self.transaction_id = transaction_id
        self.is_response = is_response
        self.opcode = opcode
        self.authoritative = authoritative
        self.truncated = truncated
        self.recursion_desired = recursion_desired
        self.recursion_available = recursion_available
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "id": f"0x{self.transaction_id:04x}",
            "type": "Response" if self.is_response else "Query",
            "opcode": self.opcode,
            "rd": self.recursion_desired,
            "ra": self.recursion_available,
            "rcode": self.rcode,
            "qdcount": self.qdcount,
            "ancount": self.ancount,
        }

    @property
    def name(self) -> str:
        return "DNS"

    @property
    def header_length(self) -> int:
        return 12

    def pack(self) -> bytes:
        flags = 0
        if self.is_response: flags |= 0x8000
        flags |= (self.opcode & 0x0F) << 11
        if self.authoritative: flags |= 0x0400
        if self.truncated: flags |= 0x0200
        if self.recursion_desired: flags |= 0x0100
        if self.recursion_available: flags |= 0x0080
        flags |= (self.rcode & 0x0F)

        buf = PacketBuffer()
        buf.write_uint16_be(self.transaction_id)
        buf.write_uint16_be(flags)
        buf.write_uint16_be(self.qdcount)
        buf.write_uint16_be(self.ancount)
        buf.write_uint16_be(self.nscount)
        buf.write_uint16_be(self.arcount)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> DNSHeader:
        if buffer.remaining < 12:
            raise DissectionError("Buffer underflow unpacking DNSHeader")
        ident = buffer.read_uint16_be()
        flags = buffer.read_uint16_be()
        qd = buffer.read_uint16_be()
        an = buffer.read_uint16_be()
        ns = buffer.read_uint16_be()
        ar = buffer.read_uint16_be()

        return cls(
            transaction_id=ident,
            is_response=bool(flags & 0x8000),
            opcode=(flags >> 11) & 0x0F,
            authoritative=bool(flags & 0x0400),
            truncated=bool(flags & 0x0200),
            recursion_desired=bool(flags & 0x0100),
            recursion_available=bool(flags & 0x0080),
            rcode=flags & 0x0F,
            qdcount=qd,
            ancount=an,
            nscount=ns,
            arcount=ar,
        )


class DNSQuestion:
    """DNS Question section."""
    def __init__(self, qname: str, qtype: DNSType = DNSType.A, qclass: DNSClass = DNSClass.IN):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_bytes(encode_dns_name(self.qname))
        buf.write_uint16_be(int(self.qtype))
        buf.write_uint16_be(int(self.qclass))
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> DNSQuestion:
        name = decode_dns_name(buffer)
        qtype = buffer.read_uint16_be()
        qclass = buffer.read_uint16_be()
        qt = DNSType(qtype) if qtype in DNSType._value2member_map_ else DNSType.A
        qc = DNSClass(qclass) if qclass in DNSClass._value2member_map_ else DNSClass.IN
        return cls(name, qt, qc)


class DNSRR:
    """DNS Resource Record section (Answers, Authorities, Additionals)."""
    def __init__(self, name: str, rtype: DNSType, rclass: DNSClass, ttl: int, rdata: bytes):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_bytes(encode_dns_name(self.name))
        buf.write_uint16_be(int(self.rtype))
        buf.write_uint16_be(int(self.rclass))
        buf.write_uint32_be(self.ttl)
        buf.write_uint16_be(len(self.rdata))
        buf.write_bytes(self.rdata)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> DNSRR:
        name = decode_dns_name(buffer)
        rtype = buffer.read_uint16_be()
        rclass = buffer.read_uint16_be()
        ttl = buffer.read_uint32_be()
        rdlength = buffer.read_uint16_be()
        rdata = buffer.read_bytes(rdlength)
        rt = DNSType(rtype) if rtype in DNSType._value2member_map_ else DNSType.A
        rc = DNSClass(rclass) if rclass in DNSClass._value2member_map_ else DNSClass.IN
        return cls(name, rt, rc, ttl, rdata)


class DNSMessage:
    """Complete DNS Query or Response Message."""
    def __init__(
        self,
        header: DNSHeader,
        questions: Optional[List[DNSQuestion]] = None,
        answers: Optional[List[DNSRR]] = None,
    ):
        self.header = header
        self.questions = questions or []
        self.answers = answers or []

    def pack(self) -> bytes:
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        buf = PacketBuffer()
        buf.write_bytes(self.header.pack())
        for q in self.questions:
            buf.write_bytes(q.pack())
        for a in self.answers:
            buf.write_bytes(a.pack())
        return buf.to_bytes()

    @classmethod
    def query(cls, domain: str, qtype: DNSType = DNSType.A, transaction_id: int = 0x1234) -> DNSMessage:
        hdr = DNSHeader(transaction_id=transaction_id, is_response=False, qdcount=1)
        q = DNSQuestion(qname=domain, qtype=qtype)
        return cls(header=hdr, questions=[q])
'''
    total_lines += write_code_file("netsphere/protocols/l7/dns.py", content_dns)

    # netsphere/protocols/l7/dhcp.py
    content_dhcp = '''"""
Dynamic Host Configuration Protocol (DHCPv4 - RFC 2131).
"""
from __future__ import annotations
import enum
import struct
from typing import List, Optional, Dict
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address, MACAddress
from netsphere.protocols.base import ProtocolHeader, DissectionError


class DHCPMessageType(enum.IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


class DHCPOption:
    """DHCP Option (Code 1 byte, Length 1 byte, Value bytes)."""
    def __init__(self, code: int, value: bytes = b""):
        self.code = code
        self.value = value

    @property
    def length(self) -> int:
        return len(self.value)

    def pack(self) -> bytes:
        if self.code in (0, 255):  # Pad or End
            return bytes([self.code])
        return bytes([self.code, len(self.value)]) + self.value

    @classmethod
    def message_type(cls, msg_type: DHCPMessageType) -> DHCPOption:
        return cls(53, bytes([int(msg_type)]))

    @classmethod
    def requested_ip(cls, ip: IPv4Address) -> DHCPOption:
        return cls(50, ip.packed)

    @classmethod
    def server_identifier(cls, ip: IPv4Address) -> DHCPOption:
        return cls(54, ip.packed)

    @classmethod
    def subnet_mask(cls, mask: IPv4Address) -> DHCPOption:
        return cls(1, mask.packed)

    @classmethod
    def router(cls, router_ip: IPv4Address) -> DHCPOption:
        return cls(3, router_ip.packed)

    @classmethod
    def dns_servers(cls, servers: List[IPv4Address]) -> DHCPOption:
        val = b"".join(s.packed for s in servers)
        return cls(6, val)


class DHCPMessage:
    """
    BOOTP / DHCP Packet structure (240 bytes min):
    - op (1 byte: 1=BOOTREQUEST, 2=BOOTREPLY)
    - htype (1 byte: 1=Ethernet)
    - hlen (1 byte: 6)
    - hops (1 byte)
    - xid (4 bytes Transaction ID)
    - secs (2 bytes)
    - flags (2 bytes, bit 0 = Broadcast)
    - ciaddr (4 bytes Client IP)
    - yiaddr (4 bytes 'Your' IP)
    - siaddr (4 bytes Server IP)
    - giaddr (4 bytes Gateway IP)
    - chaddr (16 bytes Client HW Address)
    - sname (64 bytes Server host name)
    - file (128 bytes Boot file name)
    - Magic Cookie: 0x63825363 (4 bytes)
    - Options (variable)
    """
    MAGIC_COOKIE = 0x63825363

    def __init__(
        self,
        op: int = 1,
        xid: int = 0x3903F326,
        chaddr: MACAddress = MACAddress("00:00:00:00:00:00"),
        ciaddr: IPv4Address = IPv4Address("0.0.0.0"),
        yiaddr: IPv4Address = IPv4Address("0.0.0.0"),
        siaddr: IPv4Address = IPv4Address("0.0.0.0"),
        giaddr: IPv4Address = IPv4Address("0.0.0.0"),
        flags: int = 0,
        options: Optional[List[DHCPOption]] = None,
    ):
        self.op = op
        self.htype = 1
        self.hlen = 6
        self.hops = 0
        self.xid = xid
        self.secs = 0
        self.flags = flags
        self.ciaddr = ciaddr
        self.yiaddr = yiaddr
        self.siaddr = siaddr
        self.giaddr = giaddr
        self.chaddr = chaddr
        self.options = options or []

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(self.op)
        buf.write_uint8(self.htype)
        buf.write_uint8(self.hlen)
        buf.write_uint8(self.hops)
        buf.write_uint32_be(self.xid)
        buf.write_uint16_be(self.secs)
        buf.write_uint16_be(self.flags)
        buf.write_bytes(self.ciaddr.packed)
        buf.write_bytes(self.yiaddr.packed)
        buf.write_bytes(self.siaddr.packed)
        buf.write_bytes(self.giaddr.packed)

        # 16-byte chaddr
        ch_bytes = bytearray(self.chaddr.raw_bytes)
        ch_bytes.extend(b"\\x00" * (16 - len(ch_bytes)))
        buf.write_bytes(ch_bytes)

        # 64-byte sname + 128-byte file
        buf.write_bytes(b"\\x00" * 64)
        buf.write_bytes(b"\\x00" * 128)

        # DHCP Magic Cookie
        buf.write_uint32_be(self.MAGIC_COOKIE)

        # Options
        for opt in self.options:
            buf.write_bytes(opt.pack())
        buf.write_uint8(255)  # End Option

        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> DHCPMessage:
        if buffer.remaining < 240:
            raise DissectionError("Buffer underflow unpacking DHCP packet")
        op = buffer.read_uint8()
        htype = buffer.read_uint8()
        hlen = buffer.read_uint8()
        hops = buffer.read_uint8()
        xid = buffer.read_uint32_be()
        secs = buffer.read_uint16_be()
        flags = buffer.read_uint16_be()
        ciaddr = IPv4Address(buffer.read_bytes(4))
        yiaddr = IPv4Address(buffer.read_bytes(4))
        siaddr = IPv4Address(buffer.read_bytes(4))
        giaddr = IPv4Address(buffer.read_bytes(4))
        chaddr = MACAddress(buffer.read_bytes(6))
        buffer.read_bytes(10)  # chaddr padding
        buffer.read_bytes(64)  # sname
        buffer.read_bytes(128) # file

        magic = buffer.read_uint32_be()
        options = []
        if magic == cls.MAGIC_COOKIE:
            while buffer.remaining > 0:
                code = buffer.read_uint8()
                if code == 255:  # End
                    break
                elif code == 0:  # Pad
                    continue
                if buffer.remaining < 1:
                    break
                opt_len = buffer.read_uint8()
                if buffer.remaining < opt_len:
                    break
                val = buffer.read_bytes(opt_len)
                options.append(DHCPOption(code, val))

        return cls(
            op=op,
            xid=xid,
            chaddr=chaddr,
            ciaddr=ciaddr,
            yiaddr=yiaddr,
            siaddr=siaddr,
            giaddr=giaddr,
            flags=flags,
            options=options,
        )
'''
    total_lines += write_code_file("netsphere/protocols/l7/dhcp.py", content_dhcp)

    # netsphere/protocols/l7/http1.py
    content_http1 = '''"""
Hypertext Transfer Protocol Version 1.1 (HTTP/1.1 - RFC 7230).
"""
from __future__ import annotations
from typing import Dict, Optional, Tuple


class HTTP1Request:
    """HTTP/1.1 Request model."""
    def __init__(
        self,
        method: str = "GET",
        path: str = "/",
        version: str = "HTTP/1.1",
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
    ):
        self.method = method.upper()
        self.path = path
        self.version = version
        self.headers = headers or {"Host": "localhost", "User-Agent": "NetSphere/1.0"}
        self.body = body

    def pack(self) -> bytes:
        lines = [f"{self.method} {self.path} {self.version}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        if self.body and "Content-Length" not in self.headers:
            lines.append(f"Content-Length: {len(self.body)}")
        header_text = "\\r\\n".join(lines) + "\\r\\n\\r\\n"
        return header_text.encode("latin1") + self.body

    @classmethod
    def unpack(cls, data: bytes) -> HTTP1Request:
        header_sep = b"\\r\\n\\r\\n"
        if header_sep not in data:
            header_sep = b"\\n\\n"
            if header_sep not in data:
                raise ValueError("Malformed HTTP/1.1 Request (missing header delimiter)")

        raw_headers, body = data.split(header_sep, 1)
        lines = raw_headers.decode("latin1", errors="replace").splitlines()
        if not lines:
            raise ValueError("Empty HTTP/1.1 Request")

        request_line = lines[0].split()
        if len(request_line) < 3:
            raise ValueError(f"Malformed HTTP request line: {lines[0]}")
        method, path, version = request_line[0], request_line[1], request_line[2]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        return cls(method=method, path=path, version=version, headers=headers, body=body)


class HTTP1Response:
    """HTTP/1.1 Response model."""
    def __init__(
        self,
        status_code: int = 200,
        reason: str = "OK",
        version: str = "HTTP/1.1",
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
    ):
        self.status_code = status_code
        self.reason = reason
        self.version = version
        self.headers = headers or {"Server": "NetSphere-Server/1.0", "Content-Type": "text/plain"}
        self.body = body

    def pack(self) -> bytes:
        lines = [f"{self.version} {self.status_code} {self.reason}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        if "Content-Length" not in self.headers:
            lines.append(f"Content-Length: {len(self.body)}")
        header_text = "\\r\\n".join(lines) + "\\r\\n\\r\\n"
        return header_text.encode("latin1") + self.body

    @classmethod
    def unpack(cls, data: bytes) -> HTTP1Response:
        header_sep = b"\\r\\n\\r\\n"
        if header_sep not in data:
            header_sep = b"\\n\\n"
            if header_sep not in data:
                raise ValueError("Malformed HTTP/1.1 Response")

        raw_headers, body = data.split(header_sep, 1)
        lines = raw_headers.decode("latin1", errors="replace").splitlines()
        status_line = lines[0].split(maxsplit=2)
        version = status_line[0]
        status_code = int(status_line[1])
        reason = status_line[2] if len(status_line) > 2 else "OK"

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        return cls(status_code=status_code, reason=reason, version=version, headers=headers, body=body)
'''
    total_lines += write_code_file("netsphere/protocols/l7/http1.py", content_http1)

    # netsphere/protocols/l7/http2.py
    content_http2 = '''"""
Hypertext Transfer Protocol Version 2 (HTTP/2 - RFC 7540).
"""
from __future__ import annotations
import enum
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.base import DissectionError


class HTTP2FrameType(enum.IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9


class HTTP2Frame:
    """
    HTTP/2 Fixed 9-octet Header:
    - Length (24 bits)
    - Type (8 bits)
    - Flags (8 bits)
    - R (1 bit reserved) + Stream Identifier (31 bits)
    Followed by Frame Payload.
    """
    CLIENT_PREFACE = b"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"

    def __init__(
        self,
        frame_type: HTTP2FrameType = HTTP2FrameType.SETTINGS,
        flags: int = 0,
        stream_id: int = 0,
        payload: bytes = b"",
    ):
        self.frame_type = frame_type
        self.flags = flags
        self.stream_id = stream_id
        self.payload = payload

    @property
    def length(self) -> int:
        return len(self.payload)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint24_be(self.length)
        buf.write_uint8(int(self.frame_type))
        buf.write_uint8(self.flags)
        buf.write_uint32_be(self.stream_id & 0x7FFFFFFF)
        buf.write_bytes(self.payload)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> HTTP2Frame:
        if buffer.remaining < 9:
            raise DissectionError("Buffer underflow unpacking HTTP/2 frame")
        length = buffer.read_uint24_be()
        f_type = buffer.read_uint8()
        flags = buffer.read_uint8()
        stream_id = buffer.read_uint32_be() & 0x7FFFFFFF

        if buffer.remaining < length:
            raise DissectionError(f"Buffer underflow reading HTTP/2 payload ({length} bytes)")
        payload = buffer.read_bytes(length)
        frame_t = HTTP2FrameType(f_type) if f_type in HTTP2FrameType._value2member_map_ else HTTP2FrameType.DATA
        return cls(frame_type=frame_t, flags=flags, stream_id=stream_id, payload=payload)
'''
    total_lines += write_code_file("netsphere/protocols/l7/http2.py", content_http2)

    # netsphere/protocols/l7/mqtt.py
    content_mqtt = '''"""
MQ Telemetry Transport (MQTT v3.1.1 & v5.0 - OASIS Standard).
"""
from __future__ import annotations
import enum
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.base import DissectionError


class MQTTMessageType(enum.IntEnum):
    CONNECT = 1
    CONNACK = 2
    PUBLISH = 3
    PUBACK = 4
    PUBREC = 5
    PUBREL = 6
    PUBCOMP = 7
    SUBSCRIBE = 8
    SUBACK = 9
    UNSUBSCRIBE = 10
    UNSUBACK = 11
    PINGREQ = 12
    PINGRESP = 13
    DISCONNECT = 14
    AUTH = 15


class MQTTMessage:
    """
    MQTT Control Packet:
    - Fixed Header:
        - Packet Type (4 bits) + Flags (4 bits)
        - Remaining Length (Variable Byte Integer, 1-4 bytes)
    - Variable Header & Payload
    """
    def __init__(
        self,
        msg_type: MQTTMessageType = MQTTMessageType.CONNECT,
        flags: int = 0,
        variable_header: bytes = b"",
        payload: bytes = b"",
    ):
        self.msg_type = msg_type
        self.flags = flags
        self.variable_header = variable_header
        self.payload = payload

    @classmethod
    def publish(cls, topic: str, message: bytes, qos: int = 0, retain: bool = False) -> MQTTMessage:
        flags = ((qos & 0x03) << 1) | (1 if retain else 0)
        t_bytes = topic.encode("utf-8")
        vh = bytearray()
        vh.extend(len(t_bytes).to_bytes(2, "big"))
        vh.extend(t_bytes)
        return cls(MQTTMessageType.PUBLISH, flags, bytes(vh), message)

    def pack(self) -> bytes:
        total_remaining = len(self.variable_header) + len(self.payload)
        buf = PacketBuffer()
        b1 = ((int(self.msg_type) & 0x0F) << 4) | (self.flags & 0x0F)
        buf.write_uint8(b1)

        # Variable byte integer encoding
        rem = total_remaining
        while True:
            byte = rem % 128
            rem //= 128
            if rem > 0:
                byte |= 0x80
            buf.write_uint8(byte)
            if rem == 0:
                break

        buf.write_bytes(self.variable_header)
        buf.write_bytes(self.payload)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> MQTTMessage:
        if buffer.remaining < 2:
            raise DissectionError("Buffer underflow unpacking MQTT")
        b1 = buffer.read_uint8()
        m_type = (b1 >> 4) & 0x0F
        flags = b1 & 0x0F

        # Decode variable byte length
        multiplier = 1
        rem_len = 0
        while True:
            b = buffer.read_uint8()
            rem_len += (b & 0x7F) * multiplier
            multiplier *= 128
            if not (b & 0x80):
                break

        if buffer.remaining < rem_len:
            raise DissectionError("Buffer underflow reading MQTT payload")
        data = buffer.read_bytes(rem_len)
        msg_t = MQTTMessageType(m_type) if m_type in MQTTMessageType._value2member_map_ else MQTTMessageType.CONNECT
        return cls(msg_type=msg_t, flags=flags, variable_header=b"", payload=data)
'''
    total_lines += write_code_file("netsphere/protocols/l7/mqtt.py", content_mqtt)

    # netsphere/protocols/l7/coap.py
    content_coap = '''"""
Constrained Application Protocol (CoAP - RFC 7252).
"""
from __future__ import annotations
import enum
from typing import List, Tuple
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.base import DissectionError


class CoAPType(enum.IntEnum):
    CONFIRMABLE = 0
    NON_CONFIRMABLE = 1
    ACKNOWLEDGEMENT = 2
    RESET = 3


class CoAPCode(enum.IntEnum):
    EMPTY = 0
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4
    CREATED = 65      # 2.01
    DELETED = 66      # 2.02
    VALID = 67        # 2.03
    CHANGED = 68      # 2.04
    CONTENT = 69      # 2.05
    BAD_REQUEST = 128 # 4.00
    NOT_FOUND = 132   # 4.04


class CoAPMessage:
    """
    CoAP Fixed 4-byte Header (RFC 7252):
    - Version (2 bits)
    - Type (2 bits)
    - Token Length (4 bits)
    - Code (8 bits, class.detail)
    - Message ID (16 bits)
    Followed by Token (0-8 bytes), Options, and 0xFF Payload Marker.
    """
    def __init__(
        self,
        coap_type: CoAPType = CoAPType.CONFIRMABLE,
        code: CoAPCode = CoAPCode.GET,
        message_id: int = 0x1234,
        token: bytes = b"",
        payload: bytes = b"",
    ):
        self.version = 1
        self.coap_type = coap_type
        self.code = code
        self.message_id = message_id
        self.token = token
        self.payload = payload

    def pack(self) -> bytes:
        tkl = len(self.token) & 0x0F
        b1 = (self.version << 6) | ((int(self.coap_type) & 0x03) << 4) | tkl
        buf = PacketBuffer()
        buf.write_uint8(b1)
        buf.write_uint8(int(self.code))
        buf.write_uint16_be(self.message_id)
        buf.write_bytes(self.token)
        if self.payload:
            buf.write_uint8(0xFF)  # Payload marker
            buf.write_bytes(self.payload)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> CoAPMessage:
        if buffer.remaining < 4:
            raise DissectionError("Buffer underflow unpacking CoAP")
        b1 = buffer.read_uint8()
        t = (b1 >> 4) & 0x03
        tkl = b1 & 0x0F
        code = buffer.read_uint8()
        mid = buffer.read_uint16_be()
        token = buffer.read_bytes(tkl) if tkl > 0 else b""

        payload = b""
        if buffer.remaining > 0 and buffer.peek_bytes(1) == b"\\xff":
            buffer.read_uint8()  # Consume 0xFF marker
            payload = buffer.read_bytes(buffer.remaining)

        coap_t = CoAPType(t) if t in CoAPType._value2member_map_ else CoAPType.CONFIRMABLE
        coap_c = CoAPCode(code) if code in CoAPCode._value2member_map_ else CoAPCode.EMPTY
        return cls(coap_type=coap_t, code=coap_c, message_id=mid, token=token, payload=payload)
'''
    total_lines += write_code_file("netsphere/protocols/l7/coap.py", content_coap)

    # netsphere/protocols/l7/snmp.py
    content_snmp = '''"""
Simple Network Management Protocol (SNMP v1/v2c/v3 - RFC 1157 / RFC 3416).
"""
from __future__ import annotations
import enum
from typing import List, Tuple, Any
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.base import DissectionError


class SNMPType(enum.IntEnum):
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30
    GET_REQUEST = 0xA0
    GET_NEXT_REQUEST = 0xA1
    GET_RESPONSE = 0xA2
    SET_REQUEST = 0xA3
    TRAP = 0xA4
    GET_BULK_REQUEST = 0xA5
    INFORM_REQUEST = 0xA6
    SNMPV2_TRAP = 0xA7


def encode_ber_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    len_bytes = []
    while length > 0:
        len_bytes.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(len_bytes)] + len_bytes)


def encode_ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_ber_length(len(value)) + value


class SNMPPDU:
    """SNMP Protocol Data Unit."""
    def __init__(self, pdu_type: SNMPType, request_id: int, error_status: int = 0, error_index: int = 0):
        self.pdu_type = pdu_type
        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        self.varbinds: List[Tuple[str, Any]] = []

    def add_varbind(self, oid: str, value: Any = None):
        self.varbinds.append((oid, value))

    def pack(self) -> bytes:
        content = bytearray()
        content.extend(encode_ber_tlv(SNMPType.INTEGER, self.request_id.to_bytes(4, "big")))
        content.extend(encode_ber_tlv(SNMPType.INTEGER, self.error_status.to_bytes(1, "big")))
        content.extend(encode_ber_tlv(SNMPType.INTEGER, self.error_index.to_bytes(1, "big")))
        # Empty varbind sequence
        content.extend(encode_ber_tlv(SNMPType.SEQUENCE, b""))
        return encode_ber_tlv(int(self.pdu_type), bytes(content))


class SNMPMessage:
    """
    SNMP Message (RFC 1157):
    SEQUENCE {
        version INTEGER (0=v1, 1=v2c)
        community OCTET STRING
        data ANY (PDU)
    }
    """
    def __init__(self, version: int = 1, community: str = "public", pdu: Optional[SNMPPDU] = None):
        self.version = version
        self.community = community
        self.pdu = pdu or SNMPPDU(SNMPType.GET_REQUEST, 1)

    def pack(self) -> bytes:
        seq = bytearray()
        seq.extend(encode_ber_tlv(SNMPType.INTEGER, bytes([self.version])))
        seq.extend(encode_ber_tlv(SNMPType.OCTET_STRING, self.community.encode("ascii")))
        seq.extend(self.pdu.pack())
        return encode_ber_tlv(SNMPType.SEQUENCE, bytes(seq))
'''
    total_lines += write_code_file("netsphere/protocols/l7/snmp.py", content_snmp)

    # netsphere/protocols/l7/bgp.py
    content_bgp = '''"""
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
    - Marker: 16 bytes (all 1s, \\xff*16)
    - Length: 2 bytes
    - Type: 1 byte
    Followed by Message Body.
    """
    MARKER = b"\\xff" * 16

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
'''
    total_lines += write_code_file("netsphere/protocols/l7/bgp.py", content_bgp)

    # netsphere/protocols/l7/ospf.py
    content_ospf = '''"""
Open Shortest Path First Version 2 (OSPFv2 - RFC 2328).
"""
from __future__ import annotations
import enum
import struct
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address
from netsphere.core.checksum import calculate_internet_checksum
from netsphere.protocols.base import DissectionError


class OSPFType(enum.IntEnum):
    HELLO = 1
    DATABASE_DESCRIPTION = 2
    LINK_STATE_REQUEST = 3
    LINK_STATE_UPDATE = 4
    LINK_STATE_ACK = 5


class OSPFMessage:
    """
    OSPF Header (24 bytes):
    - Version: 2 (1 byte)
    - Type: 1 byte
    - Packet Length: 2 bytes
    - Router ID: 4 bytes
    - Area ID: 4 bytes
    - Checksum: 2 bytes
    - AuType: 2 bytes
    - Authentication: 8 bytes
    Followed by OSPF payload.
    """
    def __init__(
        self,
        ospf_type: OSPFType = OSPFType.HELLO,
        router_id: IPv4Address = IPv4Address("10.0.0.1"),
        area_id: IPv4Address = IPv4Address("0.0.0.0"),
        payload: bytes = b"",
    ):
        self.version = 2
        self.ospf_type = ospf_type
        self.router_id = router_id
        self.area_id = area_id
        self.checksum = 0
        self.autype = 0
        self.payload = payload

    @property
    def length(self) -> int:
        return 24 + len(self.payload)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint8(self.version)
        buf.write_uint8(int(self.ospf_type))
        buf.write_uint16_be(self.length)
        buf.write_bytes(self.router_id.packed)
        buf.write_bytes(self.area_id.packed)
        buf.write_uint16_be(0)  # Checksum placeholder
        buf.write_uint16_be(self.autype)
        buf.write_bytes(b"\\x00" * 8)
        buf.write_bytes(self.payload)

        raw = buf.to_bytes()
        csum = calculate_internet_checksum(raw[:24] + self.payload)
        self.checksum = csum
        buf.overwrite_at(12, struct.pack("!H", csum))
        return buf.to_bytes()
'''
    total_lines += write_code_file("netsphere/protocols/l7/ospf.py", content_ospf)

    # netsphere/protocols/l7/ntp.py
    content_ntp = '''"""
Network Time Protocol Version 4 (NTPv4 - RFC 5905).
"""
from __future__ import annotations
import time
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.base import DissectionError


class NTPMessage:
    """
    NTP Packet Header (48 bytes):
    - Leap Indicator (2 bits) + Version (3 bits) + Mode (3 bits)
    - Stratum (1 byte)
    - Poll (1 byte)
    - Precision (1 byte signed)
    - Root Delay (4 bytes fixed point)
    - Root Dispersion (4 bytes fixed point)
    - Reference ID (4 bytes)
    - Reference Timestamp (8 bytes)
    - Origin Timestamp (8 bytes)
    - Receive Timestamp (8 bytes)
    - Transmit Timestamp (8 bytes)
    """
    NTP_DELTA = 2208988800  # Seconds between 1 Jan 1900 and 1 Jan 1970

    def __init__(
        self,
        leap_indicator: int = 0,
        version: int = 4,
        mode: int = 3, # 3=Client, 4=Server
        stratum: int = 2,
        poll: int = 4,
        precision: int = -6,
    ):
        self.leap_indicator = leap_indicator
        self.version = version
        self.mode = mode
        self.stratum = stratum
        self.poll = poll
        self.precision = precision
        self.transmit_timestamp: float = time.time()

    def pack(self) -> bytes:
        b1 = ((self.leap_indicator & 0x03) << 6) | ((self.version & 0x07) << 3) | (self.mode & 0x07)
        buf = PacketBuffer()
        buf.write_uint8(b1)
        buf.write_uint8(self.stratum)
        buf.write_uint8(self.poll)
        buf.write_int8(self.precision)
        buf.write_uint32_be(0) # Root delay
        buf.write_uint32_be(0) # Root dispersion
        buf.write_bytes(b"LOCL")
        buf.write_bytes(b"\\x00" * 24) # Ref, Orig, Recv timestamps

        # Transmit timestamp (64-bit NTP timestamp)
        secs = int(self.transmit_timestamp + self.NTP_DELTA)
        frac = int((self.transmit_timestamp % 1.0) * (2**32))
        buf.write_uint32_be(secs)
        buf.write_uint32_be(frac)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> NTPMessage:
        if buffer.remaining < 48:
            raise DissectionError("Buffer underflow unpacking NTP packet")
        b1 = buffer.read_uint8()
        li = (b1 >> 6) & 0x03
        ver = (b1 >> 3) & 0x07
        mode = b1 & 0x07
        strat = buffer.read_uint8()
        poll = buffer.read_uint8()
        prec = buffer.read_int8()
        buffer.read_bytes(36)
        secs = buffer.read_uint32_be()
        frac = buffer.read_uint32_be()
        ts = (secs - cls.NTP_DELTA) + (frac / (2**32))

        msg = cls(leap_indicator=li, version=ver, mode=mode, stratum=strat, poll=poll, precision=prec)
        msg.transmit_timestamp = ts
        return msg
'''
    total_lines += write_code_file("netsphere/protocols/l7/ntp.py", content_ntp)

    # netsphere/protocols/l7/syslog.py
    content_syslog = '''"""
The Syslog Protocol (RFC 5424 / RFC 3164).
"""
from __future__ import annotations
import enum
import time


class SyslogFacility(enum.IntEnum):
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(enum.IntEnum):
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


class SyslogMessage:
    """RFC 5424 Syslog Message."""
    def __init__(
        self,
        facility: SyslogFacility = SyslogFacility.DAEMON,
        severity: SyslogSeverity = SyslogSeverity.INFORMATIONAL,
        hostname: str = "netsphere-core",
        app_name: str = "netsphere",
        proc_id: str = "-",
        msg_id: str = "-",
        message: str = "System operational",
    ):
        self.facility = facility
        self.severity = severity
        self.hostname = hostname
        self.app_name = app_name
        self.proc_id = proc_id
        self.msg_id = msg_id
        self.message = message

    @property
    def priority(self) -> int:
        return (int(self.facility) * 8) + int(self.severity)

    def pack(self) -> bytes:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Format: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG
        line = f"<{self.priority}>1 {ts} {self.hostname} {self.app_name} {self.proc_id} {self.msg_id} - {self.message}"
        return line.encode("utf-8")
'''
    total_lines += write_code_file("netsphere/protocols/l7/syslog.py", content_syslog)

    # netsphere/protocols/l7/websocket.py
    content_ws = '''"""
The WebSocket Protocol (RFC 6455).
"""
from __future__ import annotations
import enum
import os
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.base import DissectionError


class WebSocketOpcode(enum.IntEnum):
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


class WebSocketFrame:
    """
    WebSocket Frame (RFC 6455):
    - FIN (1 bit), RSV1-3 (3 bits), Opcode (4 bits)
    - MASK (1 bit), Payload Length (7 bits, 16 bits, or 64 bits)
    - Masking-key (4 bytes, present if MASK bit set)
    - Payload Data (unmasked or masked)
    """
    def __init__(
        self,
        opcode: WebSocketOpcode = WebSocketOpcode.TEXT,
        payload: bytes = b"",
        fin: bool = True,
        is_masked: bool = False,
        masking_key: Optional[bytes] = None,
    ):
        self.fin = fin
        self.opcode = opcode
        self.payload = payload
        self.is_masked = is_masked
        self.masking_key = masking_key or (os.urandom(4) if is_masked else None)

    @classmethod
    def text(cls, text_str: str, mask: bool = False) -> WebSocketFrame:
        return cls(opcode=WebSocketOpcode.TEXT, payload=text_str.encode("utf-8"), is_masked=mask)

    @classmethod
    def ping(cls, data: bytes = b"") -> WebSocketFrame:
        return cls(opcode=WebSocketOpcode.PING, payload=data)

    @classmethod
    def pong(cls, data: bytes = b"") -> WebSocketFrame:
        return cls(opcode=WebSocketOpcode.PONG, payload=data)

    def pack(self) -> bytes:
        b1 = (0x80 if self.fin else 0x00) | (int(self.opcode) & 0x0F)
        buf = PacketBuffer()
        buf.write_uint8(b1)

        length = len(self.payload)
        mask_bit = 0x80 if self.is_masked else 0x00

        if length <= 125:
            buf.write_uint8(mask_bit | length)
        elif length <= 65535:
            buf.write_uint8(mask_bit | 126)
            buf.write_uint16_be(length)
        else:
            buf.write_uint8(mask_bit | 127)
            buf.write_uint64_be(length)

        if self.is_masked and self.masking_key:
            buf.write_bytes(self.masking_key)
            masked_data = bytearray(self.payload)
            for i in range(len(masked_data)):
                masked_data[i] ^= self.masking_key[i % 4]
            buf.write_bytes(masked_data)
        else:
            buf.write_bytes(self.payload)

        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> WebSocketFrame:
        if buffer.remaining < 2:
            raise DissectionError("Buffer underflow unpacking WebSocket frame")
        b1 = buffer.read_uint8()
        fin = bool(b1 & 0x80)
        opcode_val = b1 & 0x0F
        b2 = buffer.read_uint8()
        has_mask = bool(b2 & 0x80)
        len_byte = b2 & 0x7F

        if len_byte <= 125:
            length = len_byte
        elif len_byte == 126:
            length = buffer.read_uint16_be()
        else:
            length = buffer.read_uint64_be()

        mask_key = buffer.read_bytes(4) if has_mask else None
        raw_payload = buffer.read_bytes(length)

        if has_mask and mask_key:
            payload = bytearray(raw_payload)
            for i in range(len(payload)):
                payload[i] ^= mask_key[i % 4]
            final_data = bytes(payload)
        else:
            final_data = raw_payload

        op = WebSocketOpcode(opcode_val) if opcode_val in WebSocketOpcode._value2member_map_ else WebSocketOpcode.TEXT
        return cls(opcode=op, payload=final_data, fin=fin, is_masked=has_mask, masking_key=mask_key)
'''
    total_lines += write_code_file("netsphere/protocols/l7/websocket.py", content_ws)

    print(f"[*] Completed Protocols L4 & L7 generation: {total_lines:,} LOC")
    return total_lines

if __name__ == "__main__":
    generate_protocols_l4_l7()
