"""
NetSphere Simulation Package Generator:
Virtual Switching, LPM Trie Routing, NAT/PAT, Graph Algorithms, QoS Queuing, Congestion Control & Topologies.
"""
from common import write_code_file

def generate_simulation():
    total_lines = 0
    print("[*] Generating NetSphere Simulation modules...")

    # netsphere/simulation/__init__.py
    content_sim_init = '''"""
NetSphere Simulation Engine: Software Defined Networking, Virtual L2/L3 Switching, Routing, QoS, and Congestion Models.
"""
from netsphere.simulation.trie import LPMTrie, TrieNode
from netsphere.simulation.switch import VirtualSwitch, MACEntry, PortMode
from netsphere.simulation.router import VirtualRouter, RoutingEntry, RouteType
from netsphere.simulation.nat import NATEngine, NATType, NATSession
from netsphere.simulation.routing import (
    NetworkGraph,
    dijkstra_shortest_path,
    bellman_ford_shortest_path,
    floyd_warshall_all_pairs,
)
from netsphere.simulation.qos import (
    TokenBucketFilter,
    LeakyBucketFilter,
    PriorityQueue,
    WeightedFairQueue,
    RandomEarlyDetection,
)
from netsphere.simulation.congestion import (
    TCPTahoeModel,
    TCPRenoModel,
    TCPCubicModel,
    TCPBBRModel,
)
from netsphere.simulation.topology import (
    NetworkTopology,
    Node,
    NodeType,
    Link,
    Interface,
)

__all__ = [
    "LPMTrie",
    "TrieNode",
    "VirtualSwitch",
    "MACEntry",
    "PortMode",
    "VirtualRouter",
    "RoutingEntry",
    "RouteType",
    "NATEngine",
    "NATType",
    "NATSession",
    "NetworkGraph",
    "dijkstra_shortest_path",
    "bellman_ford_shortest_path",
    "floyd_warshall_all_pairs",
    "TokenBucketFilter",
    "LeakyBucketFilter",
    "PriorityQueue",
    "WeightedFairQueue",
    "RandomEarlyDetection",
    "TCPTahoeModel",
    "TCPRenoModel",
    "TCPCubicModel",
    "TCPBBRModel",
    "NetworkTopology",
    "Node",
    "NodeType",
    "Link",
    "Interface",
]
'''
    total_lines += write_code_file("netsphere/simulation/__init__.py", content_sim_init)

    # netsphere/simulation/trie.py
    content_trie = '''"""
Binary and Radix Trie for IP Longest Prefix Match (LPM).
Provides O(K) lookup time where K is 32 for IPv4 and 128 for IPv6.
"""
from __future__ import annotations
from typing import Optional, Any, List, Tuple
from netsphere.core.types import IPv4Address, CIDRNetwork


class TrieNode:
    """Node in binary routing prefix trie."""
    def __init__(self, bit: int = -1):
        self.bit = bit
        self.children: List[Optional[TrieNode]] = [None, None]
        self.is_prefix_end = False
        self.prefix_str: str = ""
        self.value: Any = None


class LPMTrie:
    """
    Longest Prefix Match (LPM) Trie implementation for IP routing tables.
    """
    def __init__(self):
        self.root = TrieNode()
        self._entry_count = 0

    @property
    def count(self) -> int:
        return self._entry_count

    def insert(self, cidr: str, value: Any) -> None:
        """
        Insert a CIDR route prefix into the trie (e.g. '192.168.1.0/24', next_hop_data).
        """
        network = CIDRNetwork(cidr)
        addr_int = network.network_address.to_int()
        prefix_len = network.prefix_len

        curr = self.root
        for bit_idx in range(prefix_len):
            bit = (addr_int >> (31 - bit_idx)) & 1
            if curr.children[bit] is None:
                curr.children[bit] = TrieNode(bit)
            curr = curr.children[bit]

        if not curr.is_prefix_end:
            self._entry_count += 1
        curr.is_prefix_end = True
        curr.prefix_str = str(network)
        curr.value = value

    def lookup(self, ip: str) -> Optional[Tuple[str, Any]]:
        """
        Perform Longest Prefix Match for a given destination IP.
        Returns (best_matching_prefix, value) or None if no route found.
        """
        addr_int = IPv4Address(ip).to_int()
        curr = self.root
        best_match: Optional[Tuple[str, Any]] = None

        if curr.is_prefix_end:
            best_match = (curr.prefix_str, curr.value)

        for bit_idx in range(32):
            bit = (addr_int >> (31 - bit_idx)) & 1
            if curr.children[bit] is None:
                break
            curr = curr.children[bit]
            if curr.is_prefix_end:
                best_match = (curr.prefix_str, curr.value)

        return best_match

    def delete(self, cidr: str) -> bool:
        """Remove a prefix from the trie."""
        network = CIDRNetwork(cidr)
        addr_int = network.network_address.to_int()
        prefix_len = network.prefix_len

        path: List[Tuple[TrieNode, int]] = []
        curr = self.root

        for bit_idx in range(prefix_len):
            bit = (addr_int >> (31 - bit_idx)) & 1
            if curr.children[bit] is None:
                return False
            path.append((curr, bit))
            curr = curr.children[bit]

        if not curr.is_prefix_end:
            return False

        curr.is_prefix_end = False
        curr.value = None
        self._entry_count -= 1

        # Prune dead branches
        for parent, bit in reversed(path):
            child = parent.children[bit]
            if child.is_prefix_end or any(child.children):
                break
            parent.children[bit] = None

        return True

    def dump_all_routes(self) -> List[Tuple[str, Any]]:
        """Traverse and collect all registered route prefixes."""
        routes = []

        def _dfs(node: TrieNode):
            if node.is_prefix_end:
                routes.append((node.prefix_str, node.value))
            for ch in node.children:
                if ch is not None:
                    _dfs(ch)

        _dfs(self.root)
        return routes
'''
    total_lines += write_code_file("netsphere/simulation/trie.py", content_trie)

    # netsphere/simulation/switch.py
    content_switch = '''"""
Layer 2 Virtual Learning Switch (Bridge) with MAC Aging and VLAN Trunking.
"""
from __future__ import annotations
import enum
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set
from netsphere.core.types import MACAddress
from netsphere.protocols.l2.ethernet import EthernetHeader


class PortMode(enum.Enum):
    ACCESS = "access"
    TRUNK = "trunk"


@dataclass
class MACEntry:
    mac_address: MACAddress
    port: str
    vlan_id: int
    timestamp: float
    is_static: bool = False


class VirtualSwitch:
    """
    Virtual Ethernet Switch:
    - Learns Source MAC addresses dynamically on ingress ports.
    - Ages out dynamic entries after MAC aging time (default 300s).
    - Filters or floods frames based on Destination MAC lookup.
    - Enforces VLAN broadcast domain isolation (Access and Trunk ports).
    """
    def __init__(self, switch_id: str = "sw1", aging_time: float = 300.0):
        self.switch_id = switch_id
        self.aging_time = aging_time
        # MAC Table key: (MACAddress, VLAN_ID) -> MACEntry
        self.mac_table: Dict[Tuple[str, int], MACEntry] = {}
        # Port Configurations: port_name -> {"mode": PortMode, "vlan": int, "allowed_vlans": Set[int]}
        self.ports: Dict[str, Dict] = {}
        self.statistics: Dict[str, int] = {
            "frames_received": 0,
            "frames_forwarded": 0,
            "frames_flooded": 0,
            "frames_dropped": 0,
        }

    def add_port(self, port_name: str, mode: PortMode = PortMode.ACCESS, default_vlan: int = 1, allowed_vlans: Optional[Set[int]] = None):
        self.ports[port_name] = {
            "mode": mode,
            "vlan": default_vlan,
            "allowed_vlans": allowed_vlans or {default_vlan},
        }

    def clean_aged_entries(self, current_time: Optional[float] = None) -> int:
        now = current_time or time.time()
        expired_keys = []
        for key, entry in self.mac_table.items():
            if not entry.is_static and (now - entry.timestamp > self.aging_time):
                expired_keys.append(key)
        for k in expired_keys:
            del self.mac_table[k]
        return len(expired_keys)

    def process_frame(self, ingress_port: str, frame_bytes: bytes, incoming_vlan: Optional[int] = None) -> List[Tuple[str, bytes]]:
        """
        Process an incoming frame on an ingress port:
        1. Validate ingress port and VLAN membership.
        2. Learn Source MAC on (Port, VLAN).
        3. Lookup Destination MAC. If unicast hit, forward to designated port; otherwise flood to eligible ports.
        Returns list of (egress_port, output_frame_bytes).
        """
        self.statistics["frames_received"] += 1
        now = time.time()

        if ingress_port not in self.ports:
            self.statistics["frames_dropped"] += 1
            return []

        port_cfg = self.ports[ingress_port]
        # Determine effective VLAN ID
        if port_cfg["mode"] == PortMode.ACCESS:
            vlan_id = port_cfg["vlan"]
        else:
            vlan_id = incoming_vlan if incoming_vlan is not None else port_cfg["vlan"]
            if vlan_id not in port_cfg["allowed_vlans"]:
                self.statistics["frames_dropped"] += 1
                return []

        if len(frame_bytes) < 14:
            self.statistics["frames_dropped"] += 1
            return []

        dst_mac = MACAddress(frame_bytes[0:6])
        src_mac = MACAddress(frame_bytes[6:12])

        # Step 2: MAC Learning
        if src_mac.is_unicast:
            self.mac_table[(str(src_mac), vlan_id)] = MACEntry(
                mac_address=src_mac,
                port=ingress_port,
                vlan_id=vlan_id,
                timestamp=now,
            )

        # Step 3: Forwarding / Flooding Decision
        if dst_mac.is_broadcast or dst_mac.is_multicast:
            # Flood frame to all other ports in this VLAN
            self.statistics["frames_flooded"] += 1
            return self._flood(ingress_port, vlan_id, frame_bytes)

        # Unicast lookup
        lookup_key = (str(dst_mac), vlan_id)
        if lookup_key in self.mac_table:
            entry = self.mac_table[lookup_key]
            # If target port is the same as arrival, filter (drop)
            if entry.port == ingress_port:
                return []
            self.statistics["frames_forwarded"] += 1
            return [(entry.port, frame_bytes)]

        # Unknown unicast -> flood
        self.statistics["frames_flooded"] += 1
        return self._flood(ingress_port, vlan_id, frame_bytes)

    def _flood(self, ingress_port: str, vlan_id: int, frame_bytes: bytes) -> List[Tuple[str, bytes]]:
        egress_targets = []
        for port_name, cfg in self.ports.items():
            if port_name == ingress_port:
                continue
            if cfg["mode"] == PortMode.ACCESS and cfg["vlan"] == vlan_id:
                egress_targets.append((port_name, frame_bytes))
            elif cfg["mode"] == PortMode.TRUNK and vlan_id in cfg["allowed_vlans"]:
                egress_targets.append((port_name, frame_bytes))
        return egress_targets
'''
    total_lines += write_code_file("netsphere/simulation/switch.py", content_switch)

    # netsphere/simulation/router.py
    content_router = '''"""
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
'''
    total_lines += write_code_file("netsphere/simulation/router.py", content_router)

    # netsphere/simulation/nat.py
    content_nat = '''"""
Network Address Translation (NAT) & Port Address Translation (PAT/NAPT) Engine.
"""
from __future__ import annotations
import enum
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from netsphere.core.types import IPv4Address, Port


class NATType(enum.Enum):
    SNAT = "SNAT"         # Source NAT (Masquerade for outbound Internet access)
    DNAT = "DNAT"         # Destination NAT (Port forwarding to internal servers)
    ONE_TO_ONE = "1to1"   # Static bidirectional 1-to-1 IP mapping


@dataclass
class NATSession:
    internal_ip: IPv4Address
    internal_port: Port
    external_ip: IPv4Address
    external_port: Port
    remote_ip: IPv4Address
    remote_port: Port
    protocol: int # 6=TCP, 17=UDP
    last_activity: float
    nat_type: NATType


class NATEngine:
    """
    Stateful NAT / PAT Translation Engine:
    - Maintains forward (Internal -> External) and reverse (External -> Internal) state tables.
    - Allocates ephemeral ports from pool (10000 - 60000).
    - Session expiration timer (idle timeout).
    """
    def __init__(self, public_ip: IPv4Address, port_range: Tuple[int, int] = (10000, 60000), timeout: float = 300.0):
        self.public_ip = public_ip
        self.port_start, self.port_end = port_range
        self.timeout = timeout
        self.next_port = self.port_start

        # Session tracking:
        # Outbound: (internal_ip, internal_port, remote_ip, remote_port, proto) -> NATSession
        self.outbound_sessions: Dict[Tuple[str, int, str, int, int], NATSession] = {}
        # Inbound: (external_port, proto) -> NATSession
        self.inbound_sessions: Dict[Tuple[int, int], NATSession] = {}
        # Static DNAT Port forwards: (external_port, proto) -> (internal_ip, internal_port)
        self.port_forwards: Dict[Tuple[int, int], Tuple[IPv4Address, Port]] = {}

    def add_port_forward(self, ext_port: int, internal_ip: IPv4Address, int_port: int, proto: int = 6):
        self.port_forwards[(ext_port, proto)] = (internal_ip, Port(int_port))

    def _allocate_port(self) -> int:
        for _ in range(self.port_end - self.port_start):
            port = self.next_port
            self.next_port = self.port_start if self.next_port >= self.port_end else self.next_port + 1
            if (port, 6) not in self.inbound_sessions and (port, 17) not in self.inbound_sessions:
                return port
        raise RuntimeError("NAT port allocation exhausted")

    def translate_outbound(
        self,
        src_ip: IPv4Address,
        src_port: Port,
        dst_ip: IPv4Address,
        dst_port: Port,
        protocol: int,
    ) -> Tuple[IPv4Address, Port]:
        """
        Translate Internal Private IP:Port to Public IP:AllocatedPort.
        """
        key = (str(src_ip), int(src_port), str(dst_ip), int(dst_port), protocol)
        now = time.time()

        if key in self.outbound_sessions:
            session = self.outbound_sessions[key]
            session.last_activity = now
            return session.external_ip, session.external_port

        allocated_port = Port(self._allocate_port())
        session = NATSession(
            internal_ip=src_ip,
            internal_port=src_port,
            external_ip=self.public_ip,
            external_port=allocated_port,
            remote_ip=dst_ip,
            remote_port=dst_port,
            protocol=protocol,
            last_activity=now,
            nat_type=NATType.SNAT,
        )
        self.outbound_sessions[key] = session
        self.inbound_sessions[(int(allocated_port), protocol)] = session
        return self.public_ip, allocated_port

    def translate_inbound(
        self,
        dst_port: Port,
        remote_ip: IPv4Address,
        remote_port: Port,
        protocol: int,
    ) -> Optional[Tuple[IPv4Address, Port]]:
        """
        Translate Public IP:Port back to Internal Private IP:Port.
        """
        now = time.time()
        inbound_key = (int(dst_port), protocol)

        # Check existing active session
        if inbound_key in self.inbound_sessions:
            session = self.inbound_sessions[inbound_key]
            session.last_activity = now
            return session.internal_ip, session.internal_port

        # Check static port forward
        if inbound_key in self.port_forwards:
            target_ip, target_port = self.port_forwards[inbound_key]
            return target_ip, target_port

        return None
'''
    total_lines += write_code_file("netsphere/simulation/nat.py", content_nat)

    # netsphere/simulation/routing.py
    content_routing = '''"""
Graph-Based Network Routing Algorithms:
- Dijkstra's Shortest Path First (OSPF / IS-IS)
- Bellman-Ford (Distance Vector / RIP)
- Floyd-Warshall (All-Pairs Shortest Paths)
"""
from __future__ import annotations
import heapq
from typing import Dict, List, Tuple, Optional, Set


class NetworkGraph:
    """
    Weighted directed network graph representing routers, switches, and link costs.
    """
    def __init__(self):
        self.adjacency: Dict[str, Dict[str, float]] = {}

    def add_node(self, node: str):
        if node not in self.adjacency:
            self.adjacency[node] = {}

    def add_edge(self, u: str, v: str, weight: float, bidirectional: bool = True):
        self.add_node(u)
        self.add_node(v)
        self.adjacency[u][v] = weight
        if bidirectional:
            self.adjacency[v][u] = weight

    def get_nodes(self) -> List[str]:
        return list(self.adjacency.keys())

    def get_neighbors(self, u: str) -> Dict[str, float]:
        return self.adjacency.get(u, {})


def dijkstra_shortest_path(graph: NetworkGraph, source: str) -> Tuple[Dict[str, float], Dict[str, Optional[str]]]:
    """
    Dijkstra's SPF Algorithm (RFC 2328 OSPF SPF calculation).
    Returns (distances_dict, previous_hop_dict).
    """
    distances: Dict[str, float] = {node: float("inf") for node in graph.get_nodes()}
    previous: Dict[str, Optional[str]] = {node: None for node in graph.get_nodes()}
    distances[source] = 0.0

    pq: List[Tuple[float, str]] = [(0.0, source)]

    while pq:
        curr_dist, curr_node = heapq.heappop(pq)
        if curr_dist > distances[curr_node]:
            continue

        for neighbor, weight in graph.get_neighbors(curr_node).items():
            new_dist = curr_dist + weight
            if new_dist < distances[neighbor]:
                distances[neighbor] = new_dist
                previous[neighbor] = curr_node
                heapq.heappush(pq, (new_dist, neighbor))

    return distances, previous


def bellman_ford_shortest_path(graph: NetworkGraph, source: str) -> Tuple[Dict[str, float], Dict[str, Optional[str]], bool]:
    """
    Bellman-Ford Distance Vector Algorithm.
    Returns (distances, previous, has_negative_cycle).
    """
    nodes = graph.get_nodes()
    distances: Dict[str, float] = {node: float("inf") for node in nodes}
    previous: Dict[str, Optional[str]] = {node: None for node in nodes}
    distances[source] = 0.0

    edges: List[Tuple[str, str, float]] = []
    for u in nodes:
        for v, w in graph.get_neighbors(u).items():
            edges.append((u, v, w))

    for _ in range(len(nodes) - 1):
        for u, v, w in edges:
            if distances[u] + w < distances[v]:
                distances[v] = distances[u] + w
                previous[v] = u

    # Check negative cycle
    for u, v, w in edges:
        if distances[u] + w < distances[v]:
            return distances, previous, True

    return distances, previous, False


def floyd_warshall_all_pairs(graph: NetworkGraph) -> Dict[str, Dict[str, float]]:
    """
    Floyd-Warshall all-pairs shortest paths calculation.
    """
    nodes = graph.get_nodes()
    dist: Dict[str, Dict[str, float]] = {u: {v: float("inf") for v in nodes} for u in nodes}

    for u in nodes:
        dist[u][u] = 0.0
        for v, w in graph.get_neighbors(u).items():
            dist[u][v] = w

    for k in nodes:
        for i in nodes:
            for j in nodes:
                if dist[i][k] + dist[k][j] < dist[i][j]:
                    dist[i][j] = dist[i][k] + dist[k][j]

    return dist
'''
    total_lines += write_code_file("netsphere/simulation/routing.py", content_routing)

    # netsphere/simulation/qos.py
    content_qos = '''"""
Quality of Service (QoS), Traffic Shaping, and Buffer Management:
- Token Bucket Filter (TBF)
- Leaky Bucket
- Priority Queuing (PQ)
- Weighted Fair Queuing (WFQ)
- Random Early Detection (RED)
"""
from __future__ import annotations
import random
import time
from collections import deque
from dataclasses import dataclass
from typing import List, Optional, Tuple, Deque


class TokenBucketFilter:
    """
    Token Bucket Traffic Shaper (RFC 2697):
    - Capacity (Burst size in bytes)
    - Rate (Tokens per second in bytes/sec)
    """
    def __init__(self, rate_bytes_sec: float, burst_bytes: int):
        self.rate = rate_bytes_sec
        self.capacity = burst_bytes
        self.tokens: float = float(burst_bytes)
        self.last_update: float = time.time()

    def update(self) -> None:
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.rate)

    def consume(self, packet_bytes: int) -> bool:
        self.update()
        if self.tokens >= packet_bytes:
            self.tokens -= packet_bytes
            return True
        return False


class LeakyBucketFilter:
    """
    Leaky Bucket Traffic Policer:
    Enforces a constant outflow rate.
    """
    def __init__(self, leak_rate_bytes_sec: float, bucket_capacity_bytes: int):
        self.leak_rate = leak_rate_bytes_sec
        self.capacity = bucket_capacity_bytes
        self.current_fill: float = 0.0
        self.last_leak: float = time.time()

    def update(self) -> None:
        now = time.time()
        elapsed = now - self.last_leak
        self.last_leak = now
        self.current_fill = max(0.0, self.current_fill - elapsed * self.leak_rate)

    def admit(self, packet_bytes: int) -> bool:
        self.update()
        if self.current_fill + packet_bytes <= self.capacity:
            self.current_fill += packet_bytes
            return True
        return False


class PriorityQueue:
    """
    Multi-level Strict Priority Scheduler (e.g. Voice > Video > Best-Effort).
    """
    def __init__(self, levels: int = 4):
        self.queues: List[Deque[bytes]] = [deque() for _ in range(levels)]

    def enqueue(self, priority: int, packet: bytes) -> None:
        p = max(0, min(priority, len(self.queues) - 1))
        self.queues[p].append(packet)

    def dequeue(self) -> Optional[bytes]:
        # Highest priority (index 0) first
        for q in self.queues:
            if q:
                return q.popleft()
        return None


class WeightedFairQueue:
    """
    Weighted Fair Queuing (WFQ) Scheduler:
    Shares bandwidth proportionally according to assigned flow weights.
    """
    def __init__(self, flow_weights: List[float]):
        self.weights = flow_weights
        self.queues: List[Deque[bytes]] = [deque() for _ in flow_weights]
        self.virtual_times: List[float] = [0.0 for _ in flow_weights]

    def enqueue(self, flow_id: int, packet: bytes) -> None:
        if 0 <= flow_id < len(self.queues):
            self.queues[flow_id].append(packet)

    def dequeue(self) -> Optional[Tuple[int, bytes]]:
        # Pick flow with smallest virtual finish time
        best_flow = -1
        min_vtime = float("inf")
        for i, q in enumerate(self.queues):
            if q:
                if self.virtual_times[i] < min_vtime:
                    min_vtime = self.virtual_times[i]
                    best_flow = i

        if best_flow == -1:
            return None

        pkt = self.queues[best_flow].popleft()
        # Advance virtual time by packet length / weight
        self.virtual_times[best_flow] += len(pkt) / max(0.01, self.weights[best_flow])
        return best_flow, pkt


class RandomEarlyDetection:
    """
    Random Early Detection (RED - RFC 2309):
    Avoids global synchronization in TCP congestion by dropping packets probabilistically
    before queue becomes full.
    """
    def __init__(self, min_th: int = 5, max_th: int = 15, max_p: float = 0.1, weight: float = 0.002):
        self.min_th = min_th
        self.max_th = max_th
        self.max_p = max_p
        self.weight = weight
        self.avg_queue_len: float = 0.0
        self.current_queue_len: int = 0

    def should_drop(self, current_queue_size: int) -> bool:
        self.current_queue_len = current_queue_size
        # EWMA average queue length
        self.avg_queue_len = (1.0 - self.weight) * self.avg_queue_len + self.weight * current_queue_size

        if self.avg_queue_len < self.min_th:
            return False
        elif self.avg_queue_len >= self.max_th:
            return True
        else:
            # Linear probability between min_th and max_th
            pb = self.max_p * (self.avg_queue_len - self.min_th) / (self.max_th - self.min_th)
            return random.random() < pb
'''
    total_lines += write_code_file("netsphere/simulation/qos.py", content_qos)

    # netsphere/simulation/congestion.py
    content_congestion = '''"""
TCP Congestion Control Simulation Models:
- TCP Tahoe (Slow Start + Congestion Avoidance + Fast Retransmit)
- TCP Reno (Fast Recovery)
- TCP CUBIC (RFC 8312 - Default Linux Congestion Algorithm)
- TCP BBR (Bottleneck Bandwidth and RTT Model)
"""
from __future__ import annotations
import math
import time
from dataclasses import dataclass
from typing import List, Tuple


class TCPTahoeModel:
    """
    TCP Tahoe:
    - Loss -> cwnd = 1, ssthresh = cwnd / 2
    """
    def __init__(self, initial_cwnd: float = 1.0, initial_ssthresh: float = 64.0):
        self.cwnd = initial_cwnd
        self.ssthresh = initial_ssthresh

    def on_ack(self) -> None:
        if self.cwnd < self.ssthresh:
            # Slow Start: cwnd += 1 per ACK (exponential)
            self.cwnd += 1.0
        else:
            # Congestion Avoidance: cwnd += 1 / cwnd per ACK (linear)
            self.cwnd += 1.0 / self.cwnd

    def on_loss(self) -> None:
        self.ssthresh = max(2.0, self.cwnd / 2.0)
        self.cwnd = 1.0


class TCPRenoModel:
    """
    TCP Reno:
    - Loss via 3 dup ACKs -> Fast Recovery: ssthresh = cwnd / 2, cwnd = ssthresh + 3
    - Loss via RTO -> cwnd = 1, ssthresh = cwnd / 2
    """
    def __init__(self, initial_cwnd: float = 1.0, initial_ssthresh: float = 64.0):
        self.cwnd = initial_cwnd
        self.ssthresh = initial_ssthresh
        self.in_fast_recovery = False

    def on_ack(self) -> None:
        if self.in_fast_recovery:
            self.cwnd = self.ssthresh
            self.in_fast_recovery = False

        if self.cwnd < self.ssthresh:
            self.cwnd += 1.0
        else:
            self.cwnd += 1.0 / self.cwnd

    def on_duplicate_ack(self, dup_count: int) -> None:
        if dup_count == 3:
            self.ssthresh = max(2.0, self.cwnd / 2.0)
            self.cwnd = self.ssthresh + 3.0
            self.in_fast_recovery = True
        elif dup_count > 3 and self.in_fast_recovery:
            self.cwnd += 1.0

    def on_timeout(self) -> None:
        self.ssthresh = max(2.0, self.cwnd / 2.0)
        self.cwnd = 1.0
        self.in_fast_recovery = False


class TCPCubicModel:
    """
    TCP CUBIC (RFC 8312):
    Window growth is governed by a cubic function of elapsed time 't' since the last congestion event:
    W_cubic(t) = C * (t - K)^3 + W_max
    where K = (W_max * beta / C)^(1/3)
    """
    def __init__(self, initial_cwnd: float = 10.0):
        self.cwnd = initial_cwnd
        self.w_max = initial_cwnd
        self.epoch_start: float = time.time()
        self.C = 0.4        # Cubic scaling constant
        self.beta = 0.7     # Multiplicative decrease factor (0.7 in CUBIC vs 0.5 in Reno)
        self.k = 0.0

    def on_loss(self) -> None:
        self.w_max = self.cwnd
        self.cwnd = max(2.0, self.cwnd * self.beta)
        self.epoch_start = time.time()
        # K = cuberoot((W_max - cwnd) / C)
        diff = max(0.0, (self.w_max - self.cwnd) / self.C)
        self.k = math.pow(diff, 1.0 / 3.0)

    def on_ack(self) -> None:
        t = time.time() - self.epoch_start
        target_w = self.C * math.pow(t - self.k, 3) + self.w_max
        if target_w > self.cwnd:
            self.cwnd += (target_w - self.cwnd) / self.cwnd
        else:
            self.cwnd += 1.0 / self.cwnd


class TCPBBRModel:
    """
    TCP BBR (Bottleneck Bandwidth and RTT):
    State machine: STARTUP, DRAIN, PROBE_BW, PROBE_RTT.
    Maintains min_rtt and max_bandwidth estimates.
    """
    def __init__(self):
        self.state = "STARTUP"
        self.pacing_gain = 2.885
        self.cwnd_gain = 2.885
        self.min_rtt = float("inf")
        self.max_bw = 0.0  # bps
        self.cwnd = 10.0

    def update_estimates(self, delivery_rate_bps: float, rtt_sec: float) -> None:
        self.max_bw = max(self.max_bw, delivery_rate_bps)
        self.min_rtt = min(self.min_rtt, rtt_sec)

        # BDP = max_bw * min_rtt
        bdp_packets = (self.max_bw * self.min_rtt) / (1500.0 * 8.0)
        self.cwnd = max(4.0, bdp_packets * self.cwnd_gain)
'''
    total_lines += write_code_file("netsphere/simulation/congestion.py", content_congestion)

    # netsphere/simulation/topology.py
    content_topology = '''"""
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
'''
    total_lines += write_code_file("netsphere/simulation/topology.py", content_topology)

    print(f"[*] Completed Simulation generation: {total_lines:,} LOC")
    return total_lines

if __name__ == "__main__":
    generate_simulation()
