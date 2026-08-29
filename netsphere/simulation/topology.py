"""
Network Topology Graph Model:
Nodes (Hosts, Switches, Routers, Firewalls), Links (Bandwidth, Latency, Loss), and Packet Flow Simulation.
"""
from __future__ import annotations
import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from netsphere.core.types import IPv4Address, MACAddress


class NodeType(enum.Enum):
    HOST = "host"
    SWITCH = "switch"
    ROUTER = "router"
    FIREWALL = "firewall"
    SERVER = "server"


@dataclass
class Interface:
    name: str
    mac_address: MACAddress
    ip_address: Optional[IPv4Address] = None
    is_up: bool = True
    speed_mbps: int = 1000


@dataclass
class Node:
    node_id: str
    node_type: NodeType
    hostname: str
    interfaces: Dict[str, Interface] = field(default_factory=dict)
    position: Tuple[int, int] = (0, 0)

    def add_interface(self, name: str, mac: str, ip: Optional[str] = None):
        self.interfaces[name] = Interface(
            name=name,
            mac_address=MACAddress(mac),
            ip_address=IPv4Address(ip) if ip else None,
        )


@dataclass
class Link:
    link_id: str
    node_a: str
    port_a: str
    node_b: str
    port_b: str
    bandwidth_mbps: float = 1000.0
    latency_ms: float = 1.0
    packet_loss_rate: float = 0.0
    is_active: bool = True


class NetworkTopology:
    """
    Manages complete simulated topology graph.
    """
    def __init__(self, name: str = "default_net"):
        self.name = name
        self.nodes: Dict[str, Node] = {}
        self.links: Dict[str, Link] = {}

    def add_node(self, node_id: str, node_type: NodeType, hostname: str, x: int = 0, y: int = 0) -> Node:
        n = Node(node_id=node_id, node_type=node_type, hostname=hostname, position=(x, y))
        self.nodes[node_id] = n
        return n

    def add_link(self, link_id: str, na: str, pa: str, nb: str, pb: str, bw: float = 1000.0, lat: float = 1.0) -> Link:
        link = Link(link_id=link_id, node_a=na, port_a=pa, node_b=nb, port_b=pb, bandwidth_mbps=bw, latency_ms=lat)
        self.links[link_id] = link
        return link

    def to_dict(self) -> Dict:
        """Export topology graph as JSON-serializable dictionary for Web Dashboard visualization."""
        return {
            "name": self.name,
            "nodes": [
                {
                    "id": n.node_id,
                    "type": n.node_type.value,
                    "label": n.hostname,
                    "x": n.position[0],
                    "y": n.position[1],
                    "interfaces": [
                        {"name": iface.name, "mac": str(iface.mac_address), "ip": str(iface.ip_address) if iface.ip_address else None}
                        for iface in n.interfaces.values()
                    ],
                }
                for n in self.nodes.values()
            ],
            "links": [
                {
                    "id": l.link_id,
                    "source": l.node_a,
                    "target": l.node_b,
                    "sourcePort": l.port_a,
                    "targetPort": l.port_b,
                    "bandwidth": l.bandwidth_mbps,
                    "latency": l.latency_ms,
                    "active": l.is_active,
                }
                for l in self.links.values()
            ],
        }
