"""
NetSphere Topology Synchronization & State Exporter.
Serializes live SDN topology graphs to JSON and Prometheus telemetry gauge models.
"""
from __future__ import annotations
import json
from typing import Dict, Any, List
from netsphere.simulation.topology import NetworkTopology, NodeType


class TopologySyncEngine:
    """Manages active topology state synchronization and exporting."""
    def __init__(self, topology: NetworkTopology):
        self.topology = topology

    def export_prometheus_metrics(self) -> str:
        """Export topology health as Prometheus exposition format."""
        lines = [
            "# HELP netsphere_nodes_total Total active topology nodes",
            "# TYPE netsphere_nodes_total gauge",
            f"netsphere_nodes_total {len(self.topology.nodes)}",
            "# HELP netsphere_links_total Total active network links",
            "# TYPE netsphere_links_total gauge",
            f"netsphere_links_total {len(self.topology.links)}",
        ]
        return "\n".join(lines) + "\n"

    def snapshot(self) -> Dict[str, Any]:
        """Generate structured snapshot."""
        return self.topology.to_dict()
