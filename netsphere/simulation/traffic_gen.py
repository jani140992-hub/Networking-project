"""
NetSphere Synthetic Traffic Generator.
Generates synthetic packet streams for load testing, jitter simulation, and throughput benchmarking.
"""
from __future__ import annotations
import time
import random
from typing import List, Dict, Any, Generator
from netsphere.protocols.base import Packet
from netsphere.protocols.l2.ethernet import EthernetHeader
from netsphere.protocols.l3.ipv4 import IPv4Header
from netsphere.protocols.l4.udp import UDPHeader
from netsphere.core.types import MACAddress, IPv4Address, Port, EtherType, TransportProtocol


class TrafficProfile:
    CONSTANT_BIT_RATE = "CBR"
    BURST = "BURST"
    POISSON = "POISSON"


class SyntheticTrafficGenerator:
    """Configurable synthetic packet generator."""
    def __init__(
        self,
        src_ip: str = "192.168.1.100",
        dst_ip: str = "10.0.0.1",
        src_port: int = 5000,
        dst_port: int = 8080,
        packet_size: int = 512,
        rate_pps: int = 100,
        profile: str = TrafficProfile.CONSTANT_BIT_RATE,
    ):
        self.src_ip = IPv4Address(src_ip)
        self.dst_ip = IPv4Address(dst_ip)
        self.src_port = Port(src_port)
        self.dst_port = Port(dst_port)
        self.packet_size = max(64, min(1500, packet_size))
        self.rate_pps = rate_pps
        self.profile = profile
        self.packets_generated = 0
        self.bytes_generated = 0

    def generate_packet(self) -> Packet:
        """Construct a single packet frame with dummy payload matching requested size."""
        eth = EthernetHeader(
            dst_mac=MACAddress("00:0c:29:4f:8e:35"),
            src_mac=MACAddress("00:50:56:c0:00:08"),
            ethertype=EtherType.IPV4,
        )
        ip = IPv4Header(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            protocol=TransportProtocol.UDP,
            ttl=64,
        )
        udp = UDPHeader(
            src_port=self.src_port,
            dst_port=self.dst_port,
        )
        header_len = 14 + 20 + 8
        payload_len = max(0, self.packet_size - header_len)
        payload = b"\x00" * payload_len

        packet = Packet(headers=[eth, ip, udp], payload=payload)
        self.packets_generated += 1
        self.bytes_generated += self.packet_size
        return packet

    def stream_batch(self, count: int) -> List[Packet]:
        """Generate a batch of packets."""
        return [self.generate_packet() for _ in range(count)]
