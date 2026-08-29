"""
NetSphere End-to-End Demonstration Script.
Demonstrates multi-layer packet construction, dissection, LPM routing, NAT translation, and diagnostics.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from netsphere.core.types import MACAddress, IPv4Address, Port, EtherType, TransportProtocol
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.base import Packet
from netsphere.protocols.l2.ethernet import EthernetHeader
from netsphere.protocols.l3.ipv4 import IPv4Header
from netsphere.protocols.l4.tcp import TCPHeader, TCPFlags, TCPOption
from netsphere.protocols.l7.http1 import HTTP1Request
from netsphere.simulation.trie import LPMTrie
from netsphere.simulation.nat import NATEngine
from netsphere.simulation.switch import VirtualSwitch, PortMode
from netsphere.catalog.ports import lookup_port
from netsphere.catalog.oui import lookup_oui
from netsphere.catalog.rfc import lookup_rfc


def run_demo():
    print("=" * 70)
    print("      NETSPHERE ENTERPRISE PROTOCOL & SIMULATION ENGINE DEMO")
    print("=" * 70)

    # 1. Packet Construction & Hex Dump
    print("\n[1] Constructing Multi-Layer Frame (Ethernet -> IPv4 -> TCP -> HTTP)...")
    eth = EthernetHeader(
        dst_mac=MACAddress("00:0c:29:4f:8e:35"),
        src_mac=MACAddress("00:50:56:c0:00:08"),
        ethertype=EtherType.IPV4,
    )
    ip = IPv4Header(
        src_ip=IPv4Address("192.168.1.100"),
        dst_ip=IPv4Address("10.0.0.1"),
        protocol=TransportProtocol.TCP,
        ttl=64,
    )
    tcp = TCPHeader(
        src_port=Port(54321),
        dst_port=Port(80),
        seq_num=1000,
        flags=TCPFlags(psh=True, ack=True),
        options=[TCPOption.mss(1460)],
    )
    http_req = HTTP1Request(method="GET", path="/api/v1/telemetry", headers={"Host": "core.netsphere.io"})

    frame = Packet(headers=[eth, ip, tcp], payload=http_req.pack())
    wire_bytes = frame.pack()

    print(f"  Frame summary: {frame.summary()}")
    print(f"  Total wire length: {len(wire_bytes)} bytes")
    print("  Hex Dump:")
    print(PacketBuffer(wire_bytes).dump_hexdump())

    # 2. Longest Prefix Match (LPM) Trie
    print("\n[2] Testing Longest Prefix Match (LPM) Trie Routing...")
    trie = LPMTrie()
    trie.insert("10.0.0.0/8", "Core-Backbone-Hop")
    trie.insert("10.1.0.0/16", "Datacenter-Distribution")
    trie.insert("10.1.10.0/24", "Server-Rack-Pod-3")
    trie.insert("0.0.0.0/0", "Transit-ISP-Gateway")

    test_ips = ["10.1.10.45", "10.1.50.2", "10.200.1.1", "198.51.100.25"]
    for tip in test_ips:
        prefix, next_hop = trie.lookup(tip)
        print(f"  IP: {tip:<16} -> LPM Match: {prefix:<16} NextHop: {next_hop}")

    # 3. NAT & PAT State Machine
    print("\n[3] Testing Stateful NAT / PAT Translation Engine...")
    nat = NATEngine(public_ip=IPv4Address("203.0.113.1"))
    pub_ip, pub_port = nat.translate_outbound(
        src_ip=IPv4Address("192.168.1.50"),
        src_port=Port(45678),
        dst_ip=IPv4Address("1.1.1.1"),
        dst_port=Port(443),
        protocol=6,
    )
    print(f"  Outbound: 192.168.1.50:45678 -> {pub_ip}:{pub_port} (Public NAT Gateway)")

    rev_ip, rev_port = nat.translate_inbound(
        dst_port=pub_port,
        remote_ip=IPv4Address("1.1.1.1"),
        remote_port=Port(443),
        protocol=6,
    )
    print(f"  Inbound:  {pub_ip}:{pub_port} -> {rev_ip}:{rev_port} (De-NAT to Internal Client)")

    # 4. Catalog Lookups
    print("\n[4] Querying IANA Standards Catalogs...")
    p_info = lookup_port(443)
    print(f"  Port 443: {p_info.service} ({p_info.transport}) - {p_info.description} [{p_info.rfc}]")

    oui_info = lookup_oui("00:0C:29")
    print(f"  OUI 00:0C:29: {oui_info.vendor} ({oui_info.device_type})")

    rfc_info = lookup_rfc(793)
    print(f"  RFC 793: {rfc_info.title} - Status: {rfc_info.status}")

    print("\n" + "=" * 70)
    print("             NETSPHERE DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()
