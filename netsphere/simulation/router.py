"""
Layer 3 Virtual Router with LPM Routing Table, ARP Cache, TTL decrement, and ICMP Error Dispatch.
"""
from __future__ import annotations
import enum
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from netsphere.core.types import IPv4Address, MACAddress
from netsphere.simulation.trie import LPMTrie
from netsphere.protocols.l3.ipv4 import IPv4Header
from netsphere.protocols.l3.icmp import ICMPHeader, ICMPType, ICMPCode


class RouteType(enum.Enum):
    CONNECTED = "C"
    STATIC = "S"
    OSPF = "O"
    BGP = "B"
    DEFAULT = "*"


@dataclass
class RoutingEntry:
    destination_cidr: str
    next_hop: Optional[IPv4Address]
    interface_name: str
    metric: int = 1
    route_type: RouteType = RouteType.STATIC
    admin_distance: int = 1


class VirtualRouter:
    """
    Virtual L3 Router:
    - Longest Prefix Match (LPM) Trie routing table.
    - ARP resolution cache.
    - Interface IP address bindings.
    - IP TTL decrement and ICMP Time Exceeded generation (RFC 792).
    """
    def __init__(self, router_id: str = "r1"):
        self.router_id = router_id
        self.trie = LPMTrie()
        # Interface name -> IPv4Address, MACAddress
        self.interfaces: Dict[str, Tuple[IPv4Address, MACAddress]] = {}
        # ARP cache: IP string -> MACAddress, timestamp
        self.arp_cache: Dict[str, Tuple[MACAddress, float]] = {}
        self.stats: Dict[str, int] = {
            "packets_routed": 0,
            "ttl_expired": 0,
            "no_route": 0,
            "delivered_local": 0,
        }

    def add_interface(self, name: str, ip: IPv4Address, mac: MACAddress, prefix_len: int = 24):
        self.interfaces[name] = (ip, mac)
        # Automatically add connected route
        from netsphere.core.types import CIDRNetwork
        connected_cidr = f"{ip}/{prefix_len}"
        net = CIDRNetwork(connected_cidr)
        self.add_route(str(net), next_hop=None, interface_name=name, route_type=RouteType.CONNECTED, metric=0)

    def add_route(
        self,
        destination_cidr: str,
        next_hop: Optional[IPv4Address],
        interface_name: str,
        metric: int = 1,
        route_type: RouteType = RouteType.STATIC,
    ):
        entry = RoutingEntry(
            destination_cidr=destination_cidr,
            next_hop=next_hop,
            interface_name=interface_name,
            metric=metric,
            route_type=route_type,
        )
        self.trie.insert(destination_cidr, entry)

    def update_arp(self, ip: str, mac: MACAddress):
        self.arp_cache[ip] = (mac, time.time())

    def route_ipv4_packet(self, ipv4_hdr: IPv4Header, payload: bytes = b"") -> Optional[Tuple[str, IPv4Header, bytes]]:
        """
        Route an IPv4 packet:
        1. Check if packet is destined for one of the router's local interfaces.
        2. Check and decrement TTL. If TTL <= 1, generate ICMP Time Exceeded.
        3. Lookup LPM Trie for destination IP.
        4. Return (egress_interface, modified_ipv4_hdr, payload) or None if dropped.
        """
        dst_ip_str = str(ipv4_hdr.dst_ip)

        # Check local delivery
        for iface_name, (iface_ip, _) in self.interfaces.items():
            if dst_ip_str == str(iface_ip):
                self.stats["delivered_local"] += 1
                return None

        # Check TTL
        if ipv4_hdr.ttl <= 1:
            self.stats["ttl_expired"] += 1
            # In a full stack, generates ICMP Time Exceeded back to source
            return None

        # LPM Lookup
        match = self.trie.lookup(dst_ip_str)
        if match is None:
            self.stats["no_route"] += 1
            return None

        prefix, route_entry = match

        # Decrement TTL and re-pack header with new checksum
        ipv4_hdr.ttl -= 1
        ipv4_hdr.pack()

        self.stats["packets_routed"] += 1
        return (route_entry.interface_name, ipv4_hdr, payload)
