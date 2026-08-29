"""
Address Resolution Protocol (ARP / RARP - RFC 826).
"""
from __future__ import annotations
import enum
import struct
from typing import Optional
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import MACAddress, IPv4Address, EtherType
from netsphere.protocols.base import ProtocolHeader, DissectionError, ProtocolRegistry


class ARPOperation(enum.IntEnum):
    REQUEST = 1
    REPLY = 2
    RARP_REQUEST = 3
    RARP_REPLY = 4
    DRARP_REQUEST = 5
    DRARP_REPLY = 6
    DRARP_ERROR = 7
    IN_ARP_REQUEST = 8
    IN_ARP_REPLY = 9


class ARPHeader(ProtocolHeader):
    """
    Ethernet / IPv4 ARP Packet (28 bytes):
    - Hardware Type: 1 (Ethernet)
    - Protocol Type: 0x0800 (IPv4)
    - Hardware Size: 6
    - Protocol Size: 4
    - Opcode: 1=Request, 2=Reply
    - Sender MAC: 6 bytes
    - Sender IP: 4 bytes
    - Target MAC: 6 bytes
    - Target IP: 4 bytes
    """
    def __init__(
        self,
        operation: ARPOperation = ARPOperation.REQUEST,
        sender_mac: MACAddress = MACAddress("00:00:00:00:00:00"),
        sender_ip: IPv4Address = IPv4Address("0.0.0.0"),
        target_mac: MACAddress = MACAddress("00:00:00:00:00:00"),
        target_ip: IPv4Address = IPv4Address("0.0.0.0"),
        hw_type: int = 1,
        proto_type: int = EtherType.IPV4,
    ):
        super().__init__()
        self.hw_type = hw_type
        self.proto_type = proto_type
        self.hw_size = 6
        self.proto_size = 4
        self.operation = operation
        self.sender_mac = sender_mac
        self.sender_ip = sender_ip
        self.target_mac = target_mac
        self.target_ip = target_ip
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "hw_type": self.hw_type,
            "proto_type": f"0x{self.proto_type:04x}",
            "hw_size": self.hw_size,
            "proto_size": self.proto_size,
            "operation": f"{self.operation.name} ({self.operation.value})",
            "sender_mac": str(self.sender_mac),
            "sender_ip": str(self.sender_ip),
            "target_mac": str(self.target_mac),
            "target_ip": str(self.target_ip),
        }

    @property
    def name(self) -> str:
        return "ARP"

    @property
    def header_length(self) -> int:
        return 28

    @property
    def is_gratuitous(self) -> bool:
        """Check if this is a Gratuitous ARP (Sender IP == Target IP)."""
        return self.sender_ip == self.target_ip

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint16_be(self.hw_type)
        buf.write_uint16_be(self.proto_type)
        buf.write_uint8(self.hw_size)
        buf.write_uint8(self.proto_size)
        buf.write_uint16_be(int(self.operation))
        buf.write_bytes(self.sender_mac.raw_bytes)
        buf.write_bytes(self.sender_ip.packed)
        buf.write_bytes(self.target_mac.raw_bytes)
        buf.write_bytes(self.target_ip.packed)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> ARPHeader:
        if buffer.remaining < 28:
            raise DissectionError("Buffer underflow unpacking ARPHeader")
        hw_type = buffer.read_uint16_be()
        proto_type = buffer.read_uint16_be()
        hw_size = buffer.read_uint8()
        proto_size = buffer.read_uint8()
        opcode_val = buffer.read_uint16_be()
        operation = ARPOperation(opcode_val) if opcode_val in ARPOperation._value2member_map_ else ARPOperation.REQUEST

        sender_mac = MACAddress(buffer.read_bytes(hw_size))
        sender_ip = IPv4Address(buffer.read_bytes(proto_size))
        target_mac = MACAddress(buffer.read_bytes(hw_size))
        target_ip = IPv4Address(buffer.read_bytes(proto_size))

        return cls(
            operation=operation,
            sender_mac=sender_mac,
            sender_ip=sender_ip,
            target_mac=target_mac,
            target_ip=target_ip,
            hw_type=hw_type,
            proto_type=proto_type,
        )


# Register ARP with ProtocolRegistry
ProtocolRegistry.register_ethertype(EtherType.ARP, ARPHeader)
