"""
REST API Router and Controllers for NetSphere Management and Telemetry.
"""
from __future__ import annotations
import json
from typing import Dict
from netsphere.server.http_server import HTTPRequest, HTTPResponse, HTTPServer
from netsphere.simulation.topology import NetworkTopology, NodeType
from netsphere.scanner.engine import PortScanner, ScanType
from netsphere.diagnostics.ping import PingClient


class APIRouter:
    """
    Mounts NetSphere REST API endpoints onto HTTPServer.
    """
    def __init__(self, server: HTTPServer, topology: NetworkTopology):
        self.server = server
        self.topology = topology
        self.scanner = PortScanner(max_workers=20, timeout=1.0)
        self._register_routes()

    def _register_routes(self):
        self.server.add_route("GET", "/api/status", self.handle_status)
        self.server.add_route("GET", "/api/topology", self.handle_get_topology)
        self.server.add_route("POST", "/api/scan", self.handle_scan)
        self.server.add_route("POST", "/api/ping", self.handle_ping)
        self.server.add_route("GET", "/api/telemetry/metrics", self.handle_metrics)

    def handle_status(self, req: HTTPRequest) -> HTTPResponse:
        return HTTPResponse.json({
            "status": "operational",
            "version": "1.0.0",
            "active_nodes": len(self.topology.nodes),
            "active_links": len(self.topology.links),
        })

    def handle_get_topology(self, req: HTTPRequest) -> HTTPResponse:
        return HTTPResponse.json(self.topology.to_dict())

    def handle_scan(self, req: HTTPRequest) -> HTTPResponse:
        try:
            body = json.loads(req.body.decode("utf-8")) if req.body else {}
            target = body.get("target", "127.0.0.1")
            ports = body.get("ports", [21, 22, 23, 25, 53, 80, 443, 8080])
            results = self.scanner.scan_range(target, ports, ScanType.TCP_CONNECT)
            return HTTPResponse.json({
                "target": target,
                "scanned_ports": len(ports),
                "results": [
                    {"port": r.port, "status": r.status.value, "service": r.service_name, "rtt_ms": round(r.rtt_ms, 2), "banner": r.banner}
                    for r in results
                ],
            })
        except Exception as e:
            return HTTPResponse.json({"error": str(e)}, status_code=400)

    def handle_ping(self, req: HTTPRequest) -> HTTPResponse:
        try:
            body = json.loads(req.body.decode("utf-8")) if req.body else {}
            target = body.get("target", "127.0.0.1")
            count = body.get("count", 4)
            pinger = PingClient(target=target, port=80, timeout=1.0)
            stats = pinger.run(count=count)
            return HTTPResponse.json({
                "target": stats.target,
                "transmitted": stats.packets_transmitted,
                "received": stats.packets_received,
                "packet_loss_pct": stats.packet_loss_percent,
                "min_ms": round(stats.min_rtt_ms, 2),
                "avg_ms": round(stats.avg_rtt_ms, 2),
                "max_ms": round(stats.max_rtt_ms, 2),
                "jitter_ms": round(stats.jitter_ms, 2),
            })
        except Exception as e:
            return HTTPResponse.json({"error": str(e)}, status_code=400)

    def handle_metrics(self, req: HTTPRequest) -> HTTPResponse:
        return HTTPResponse.json({
            "pps": 1420.5,
            "mbps": 11.36,
            "drops_per_sec": 0.0,
            "latency_p50_ms": 1.2,
            "latency_p95_ms": 3.8,
            "latency_p99_ms": 8.4,
        })
