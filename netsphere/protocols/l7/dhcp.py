"""
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
        ch_bytes.extend(b"\x00" * (16 - len(ch_bytes)))
        buf.write_bytes(ch_bytes)

        # 64-byte sname + 128-byte file
        buf.write_bytes(b"\x00" * 64)
        buf.write_bytes(b"\x00" * 128)

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
