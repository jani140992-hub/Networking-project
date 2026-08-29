"""
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
