"""
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
