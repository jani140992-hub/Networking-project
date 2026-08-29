"""
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
