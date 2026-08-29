"""
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
        if buffer.remaining > 0 and buffer.peek_bytes(1) == b"\xff":
            buffer.read_uint8()  # Consume 0xFF marker
            payload = buffer.read_bytes(buffer.remaining)

        coap_t = CoAPType(t) if t in CoAPType._value2member_map_ else CoAPType.CONFIRMABLE
        coap_c = CoAPCode(code) if code in CoAPCode._value2member_map_ else CoAPCode.EMPTY
        return cls(coap_type=coap_t, code=coap_c, message_id=mid, token=token, payload=payload)
