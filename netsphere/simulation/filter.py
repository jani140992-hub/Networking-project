"""
NetSphere Packet Filter (BPF-style Expression Matcher).
Evaluates network packet headers against filter rules (e.g., protocol, port, IP, subnet).
"""
from __future__ import annotations
import re
from typing import Dict, Any, List, Optional
from netsphere.protocols.base import Packet
from netsphere.protocols.l2.ethernet import EthernetHeader
from netsphere.protocols.l3.ipv4 import IPv4Header
from netsphere.protocols.l3.ipv6 import IPv6Header
from netsphere.protocols.l4.tcp import TCPHeader
from netsphere.protocols.l4.udp import UDPHeader


class PacketFilterRule:
    """A single filtering predicate."""
    def __init__(self, field: str, op: str, value: Any):
        self.field = field
        self.op = op
        self.value = value

    def evaluate(self, packet_dict: Dict[str, Any]) -> bool:
        if self.field not in packet_dict:
            return False
        val = packet_dict[self.field]
        if self.op == "==":
            return str(val).lower() == str(self.value).lower()
        elif self.op == "!=":
            return str(val).lower() != str(self.value).lower()
        elif self.op == ">":
            return float(val) > float(self.value)
        elif self.op == "<":
            return float(val) < float(self.value)
        elif self.op == ">=":
            return float(val) >= float(self.value)
        elif self.op == "<=":
            return float(val) <= float(self.value)
        elif self.op == "in":
            return val in self.value
        return False


class PacketFilter:
    """
    Evaluates packet frames against boolean rule expressions.
    """
    def __init__(self, expression: str = ""):
        self.expression = expression
        self.rules: List[PacketFilterRule] = []
        if expression:
            self.compile(expression)

    def compile(self, expression: str):
        """Compile a simple Wireshark-like filter expression."""
        self.expression = expression
        self.rules = []
        tokens = expression.split(" and ")
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            if "==" in token:
                f, v = token.split("==", 1)
                self.rules.append(PacketFilterRule(f.strip(), "==", v.strip()))
            elif "!=" in token:
                f, v = token.split("!=", 1)
                self.rules.append(PacketFilterRule(f.strip(), "!=", v.strip()))
            elif ">=" in token:
                f, v = token.split(">=", 1)
                self.rules.append(PacketFilterRule(f.strip(), ">=", v.strip()))
            elif "<=" in token:
                f, v = token.split("<=", 1)
                self.rules.append(PacketFilterRule(f.strip(), "<=", v.strip()))
            elif ">" in token:
                f, v = token.split(">", 1)
                self.rules.append(PacketFilterRule(f.strip(), ">", v.strip()))
            elif "<" in token:
                f, v = token.split("<", 1)
                self.rules.append(PacketFilterRule(f.strip(), "<", v.strip()))
            elif token.lower() in ("tcp", "udp", "icmp", "ipv4", "ipv6", "arp"):
                self.rules.append(PacketFilterRule("proto", "==", token.lower()))

    def extract_fields(self, packet: Packet) -> Dict[str, Any]:
        """Extract searchable key-value fields from a parsed Packet."""
        fields: Dict[str, Any] = {"length": len(packet.payload)}
        for h in packet.headers:
            if isinstance(h, EthernetHeader):
                fields["eth.src"] = str(h.src_mac)
                fields["eth.dst"] = str(h.dst_mac)
                fields["eth.type"] = h.ethertype
            elif isinstance(h, IPv4Header):
                fields["proto"] = "ipv4"
                fields["ip.src"] = str(h.src_ip)
                fields["ip.dst"] = str(h.dst_ip)
                fields["ip.ttl"] = h.ttl
                fields["ip.proto"] = h.protocol
            elif isinstance(h, IPv6Header):
                fields["proto"] = "ipv6"
                fields["ipv6.src"] = str(h.src_ip)
                fields["ipv6.dst"] = str(h.dst_ip)
            elif isinstance(h, TCPHeader):
                fields["proto"] = "tcp"
                fields["tcp.srcport"] = int(h.src_port)
                fields["tcp.dstport"] = int(h.dst_port)
                fields["tcp.flags.syn"] = bool(h.flags.syn)
                fields["tcp.flags.ack"] = bool(h.flags.ack)
                fields["port"] = int(h.dst_port)
            elif isinstance(h, UDPHeader):
                fields["proto"] = "udp"
                fields["udp.srcport"] = int(h.src_port)
                fields["udp.dstport"] = int(h.dst_port)
                fields["port"] = int(h.dst_port)
        return fields

    def matches(self, packet: Packet) -> bool:
        """Return True if packet satisfies all compiled filter rules."""
        if not self.rules:
            return True
        fields = self.extract_fields(packet)
        for rule in self.rules:
            if not rule.evaluate(fields):
                return False
        return True
