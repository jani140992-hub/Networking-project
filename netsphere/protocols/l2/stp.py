"""
IEEE 802.1D Spanning Tree Protocol (STP) and Rapid Spanning Tree Protocol (RSTP).
"""
from __future__ import annotations
import enum
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import MACAddress
from netsphere.protocols.base import ProtocolHeader, DissectionError


class BPDUType(enum.IntEnum):
    CONFIGURATION = 0x00
    TOPOLOGY_CHANGE_NOTIFICATION = 0x80
    RAPID_STP = 0x02


class STPHeader(ProtocolHeader):
    """
    STP BPDU (Bridge Protocol Data Unit):
    - Protocol Identifier: 0x0000 (2 bytes)
    - Protocol Version: 0 (STP) or 2 (RSTP) (1 byte)
    - BPDU Type: 0x00 Config, 0x80 TCN (1 byte)
    - Flags: 1 byte (TC, Proposal, Port Role, Learning, Forwarding, Agreement, TCA)
    - Root Identifier: 8 bytes (Priority 2 bytes + Root MAC 6 bytes)
    - Root Path Cost: 4 bytes
    - Bridge Identifier: 8 bytes (Priority 2 bytes + Bridge MAC 6 bytes)
    - Port Identifier: 2 bytes
    - Message Age: 2 bytes (units 1/256 sec)
    - Max Age: 2 bytes
    - Hello Time: 2 bytes
    - Forward Delay: 2 bytes
    """
    def __init__(
        self,
        bpdu_type: BPDUType = BPDUType.CONFIGURATION,
        root_priority: int = 32768,
        root_mac: MACAddress = MACAddress("00:00:00:00:00:01"),
        root_path_cost: int = 0,
        bridge_priority: int = 32768,
        bridge_mac: MACAddress = MACAddress("00:00:00:00:00:01"),
        port_id: int = 0x8001,
        message_age: int = 0,
        max_age: int = 20 * 256,
        hello_time: int = 2 * 256,
        forward_delay: int = 15 * 256,
    ):
        super().__init__()
        self.protocol_id = 0x0000
        self.version = 0
        self.bpdu_type = bpdu_type
        self.flags = 0
        self.root_priority = root_priority
        self.root_mac = root_mac
        self.root_path_cost = root_path_cost
        self.bridge_priority = bridge_priority
        self.bridge_mac = bridge_mac
        self.port_id = port_id
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay
        self._sync_fields()

    def _sync_fields(self):
        self.fields = {
            "bpdu_type": self.bpdu_type.name,
            "root_id": f"{self.root_priority} / {self.root_mac}",
            "path_cost": self.root_path_cost,
            "bridge_id": f"{self.bridge_priority} / {self.bridge_mac}",
            "port_id": f"0x{self.port_id:04x}",
            "hello_time_sec": self.hello_time / 256.0,
            "max_age_sec": self.max_age / 256.0,
            "forward_delay_sec": self.forward_delay / 256.0,
        }

    @property
    def name(self) -> str:
        return "STP"

    @property
    def header_length(self) -> int:
        return 35 if self.bpdu_type != BPDUType.TOPOLOGY_CHANGE_NOTIFICATION else 4

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint16_be(self.protocol_id)
        buf.write_uint8(self.version)
        buf.write_uint8(int(self.bpdu_type))
        if self.bpdu_type == BPDUType.TOPOLOGY_CHANGE_NOTIFICATION:
            return buf.to_bytes()

        buf.write_uint8(self.flags)
        buf.write_uint16_be(self.root_priority)
        buf.write_bytes(self.root_mac.raw_bytes)
        buf.write_uint32_be(self.root_path_cost)
        buf.write_uint16_be(self.bridge_priority)
        buf.write_bytes(self.bridge_mac.raw_bytes)
        buf.write_uint16_be(self.port_id)
        buf.write_uint16_be(self.message_age)
        buf.write_uint16_be(self.max_age)
        buf.write_uint16_be(self.hello_time)
        buf.write_uint16_be(self.forward_delay)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> STPHeader:
        if buffer.remaining < 4:
            raise DissectionError("Buffer underflow unpacking STP")
        _proto = buffer.read_uint16_be()
        _ver = buffer.read_uint8()
        b_type = buffer.read_uint8()
        bpdu_type = BPDUType(b_type) if b_type in BPDUType._value2member_map_ else BPDUType.CONFIGURATION

        if bpdu_type == BPDUType.TOPOLOGY_CHANGE_NOTIFICATION:
            return cls(bpdu_type=bpdu_type)

        if buffer.remaining < 31:
            raise DissectionError("Buffer underflow unpacking STP Configuration BPDU")
        _flags = buffer.read_uint8()
        root_pri = buffer.read_uint16_be()
        root_mac = MACAddress(buffer.read_bytes(6))
        cost = buffer.read_uint32_be()
        bridge_pri = buffer.read_uint16_be()
        bridge_mac = MACAddress(buffer.read_bytes(6))
        port_id = buffer.read_uint16_be()
        msg_age = buffer.read_uint16_be()
        max_age = buffer.read_uint16_be()
        hello = buffer.read_uint16_be()
        fwd_delay = buffer.read_uint16_be()

        return cls(
            bpdu_type=bpdu_type,
            root_priority=root_pri,
            root_mac=root_mac,
            root_path_cost=cost,
            bridge_priority=bridge_pri,
            bridge_mac=bridge_mac,
            port_id=port_id,
            message_age=msg_age,
            max_age=max_age,
            hello_time=hello,
            forward_delay=fwd_delay,
        )
