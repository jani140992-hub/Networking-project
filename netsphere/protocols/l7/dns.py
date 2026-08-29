"""
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
    """Encode domain name into DNS wire format (e.g. 'www.google.com' -> \x03www\x06google\x03com\x00)."""
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
