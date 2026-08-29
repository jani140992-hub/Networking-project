"""
IEEE 802.1AB Link Layer Discovery Protocol (LLDP).
"""
from __future__ import annotations
import enum
from typing import List, Tuple
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class LLDPTLVType(enum.IntEnum):
    END_OF_LLDPDU = 0
    CHASSIS_ID = 1
    PORT_ID = 2
    TIME_TO_LIVE = 3
    PORT_DESCRIPTION = 4
    SYSTEM_NAME = 5
    SYSTEM_DESCRIPTION = 6
    SYSTEM_CAPABILITIES = 7
    MANAGEMENT_ADDRESS = 8
    ORGANIZATION_SPECIFIC = 127


class LLDPTLV:
    """Represents an LLDP Type-Length-Value field."""
    def __init__(self, tlv_type: int, value: bytes):
        self.tlv_type = tlv_type
        self.value = value

    @property
    def length(self) -> int:
        return len(self.value)

    def pack(self) -> bytes:
        # Type is 7 bits, Length is 9 bits
        type_len = ((self.tlv_type & 0x7F) << 9) | (len(self.value) & 0x01FF)
        buf = PacketBuffer()
        buf.write_uint16_be(type_len)
        buf.write_bytes(self.value)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> LLDPTLV:
        if buffer.remaining < 2:
            raise DissectionError("Buffer underflow unpacking LLDP TLV")
        type_len = buffer.read_uint16_be()
        tlv_type = (type_len >> 9) & 0x7F
        length = type_len & 0x01FF
        if buffer.remaining < length:
            raise DissectionError(f"Buffer underflow unpacking LLDP TLV value (need {length}, got {buffer.remaining})")
        val = buffer.read_bytes(length)
        return cls(tlv_type, val)


class LLDPHeader(ProtocolHeader):
    """
    LLDP Frame payload containing mandatory and optional TLVs:
    - Mandatory: Chassis ID, Port ID, TTL, End of LLDPDU
    """
    def __init__(self, tlvs: Optional[List[LLDPTLV]] = None):
        super().__init__()
        self.tlvs: List[LLDPTLV] = tlvs or []
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "tlv_count": len(self.tlvs),
            "tlv_types": [LLDPTLVType(t.tlv_type).name if t.tlv_type in LLDPTLVType._value2member_map_ else f"Custom({t.tlv_type})" for t in self.tlvs],
        }

    @property
    def name(self) -> str:
        return "LLDP"

    @property
    def header_length(self) -> int:
        return sum(2 + t.length for t in self.tlvs)

    def pack(self) -> bytes:
        buf = PacketBuffer()
        for t in self.tlvs:
            buf.write_bytes(t.pack())
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> LLDPHeader:
        tlvs = []
        while buffer.remaining >= 2:
            tlv = LLDPTLV.unpack(buffer)
            tlvs.append(tlv)
            if tlv.tlv_type == LLDPTLVType.END_OF_LLDPDU:
                break
        return cls(tlvs)


ProtocolRegistry.register_ethertype(EtherType.LLDP, LLDPHeader)
