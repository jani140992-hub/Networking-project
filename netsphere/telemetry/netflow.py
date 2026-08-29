"""
Cisco NetFlow Version 5 Flow Export and Collection (RFC 3954 / Cisco Whitepaper).
"""
from __future__ import annotations
import struct
import time
from dataclasses import dataclass
from typing import List, Optional
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address, Port


@dataclass
class NetFlowV5Record:
    src_ip: IPv4Address
    dst_ip: IPv4Address
    next_hop: IPv4Address
    input_ifindex: int
    output_ifindex: int
    packet_count: int
    byte_count: int
    first_uptime_ms: int
    last_uptime_ms: int
    src_port: Port
    dst_port: Port
    tcp_flags: int
    protocol: int
    tos: int
    src_as: int
    dst_as: int
    src_mask: int
    dst_mask: int

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_bytes(self.src_ip.packed)
        buf.write_bytes(self.dst_ip.packed)
        buf.write_bytes(self.next_hop.packed)
        buf.write_uint16_be(self.input_ifindex)
        buf.write_uint16_be(self.output_ifindex)
        buf.write_uint32_be(self.packet_count)
        buf.write_uint32_be(self.byte_count)
        buf.write_uint32_be(self.first_uptime_ms)
        buf.write_uint32_be(self.last_uptime_ms)
        buf.write_uint16_be(int(self.src_port))
        buf.write_uint16_be(int(self.dst_port))
        buf.write_uint8(0) # pad
        buf.write_uint8(self.tcp_flags)
        buf.write_uint8(self.protocol)
        buf.write_uint8(self.tos)
        buf.write_uint16_be(self.src_as)
        buf.write_uint16_be(self.dst_as)
        buf.write_uint8(self.src_mask)
        buf.write_uint8(self.dst_mask)
        buf.write_uint16_be(0) # pad
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> NetFlowV5Record:
        src_ip = IPv4Address(buffer.read_bytes(4))
        dst_ip = IPv4Address(buffer.read_bytes(4))
        next_hop = IPv4Address(buffer.read_bytes(4))
        in_if = buffer.read_uint16_be()
        out_if = buffer.read_uint16_be()
        pkts = buffer.read_uint32_be()
        octets = buffer.read_uint32_be()
        first_ts = buffer.read_uint32_be()
        last_ts = buffer.read_uint32_be()
        src_p = Port(buffer.read_uint16_be())
        dst_p = Port(buffer.read_uint16_be())
        buffer.read_uint8() # pad
        tcp_fl = buffer.read_uint8()
        proto = buffer.read_uint8()
        tos = buffer.read_uint8()
        src_as = buffer.read_uint16_be()
        dst_as = buffer.read_uint16_be()
        src_m = buffer.read_uint8()
        dst_m = buffer.read_uint8()
        buffer.read_uint16_be() # pad

        return cls(
            src_ip=src_ip,
            dst_ip=dst_ip,
            next_hop=next_hop,
            input_ifindex=in_if,
            output_ifindex=out_if,
            packet_count=pkts,
            byte_count=octets,
            first_uptime_ms=first_ts,
            last_uptime_ms=last_ts,
            src_port=src_p,
            dst_port=dst_p,
            tcp_flags=tcp_fl,
            protocol=proto,
            tos=tos,
            src_as=src_as,
            dst_as=dst_as,
            src_mask=src_m,
            dst_mask=dst_m,
        )


class NetFlowV5Packet:
    """
    NetFlow v5 Header (24 bytes):
    - Version: 5 (2 bytes)
    - Count: 1-30 records (2 bytes)
    - SysUptime ms (4 bytes)
    - Unix Secs (4 bytes)
    - Unix Nsecs (4 bytes)
    - Flow Sequence (4 bytes)
    - Engine Type & ID (2 bytes)
    - Sampling Interval (2 bytes)
    Followed by records (48 bytes each).
    """
    def __init__(self, sequence: int = 1, records: Optional[List[NetFlowV5Record]] = None):
        self.version = 5
        self.sequence = sequence
        self.sys_uptime_ms = int(time.time() * 1000) & 0xFFFFFFFF
        self.unix_secs = int(time.time())
        self.records = records or []

    def pack(self) -> bytes:
        buf = PacketBuffer()
        buf.write_uint16_be(self.version)
        buf.write_uint16_be(len(self.records))
        buf.write_uint32_be(self.sys_uptime_ms)
        buf.write_uint32_be(self.unix_secs)
        buf.write_uint32_be(0) # nsecs
        buf.write_uint32_be(self.sequence)
        buf.write_uint8(0) # engine type
        buf.write_uint8(0) # engine id
        buf.write_uint16_be(0) # sampling

        for r in self.records:
            buf.write_bytes(r.pack())
        return buf.to_bytes()


class NetFlowCollector:
    """Collects and aggregates NetFlow flow records."""
    def __init__(self):
        self.flows: List[NetFlowV5Record] = []

    def ingest_packet(self, packet_bytes: bytes) -> int:
        buf = PacketBuffer(packet_bytes)
        if buf.remaining < 24:
            return 0
        ver = buf.read_uint16_be()
        count = buf.read_uint16_be()
        buf.read_bytes(20) # Header rest

        ingested = 0
        for _ in range(count):
            if buf.remaining < 48:
                break
            record = NetFlowV5Record.unpack(buf)
            self.flows.append(record)
            ingested += 1
        return ingested
