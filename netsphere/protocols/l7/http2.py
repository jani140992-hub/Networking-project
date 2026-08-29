"""
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
    CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

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
