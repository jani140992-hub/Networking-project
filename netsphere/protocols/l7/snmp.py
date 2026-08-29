"""
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
