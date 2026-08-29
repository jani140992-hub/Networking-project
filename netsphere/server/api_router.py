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
        self.server.add_route("POST", "/api/topology/node", self.handle_add_node)
        self.server.add_route("POST", "/api/scan", self.handle_scan)
        self.server.add_route("POST", "/api/ping", self.handle_ping)
        self.server.add_route("GET", "/api/telemetry/metrics", self.handle_metrics)
        self.server.add_route("GET", "/api/catalog/search", self.handle_catalog_search)

    def handle_status(self, req: HTTPRequest) -> HTTPResponse:
        return HTTPResponse.json({
            "status": "operational",
            "version": "1.0.0",
            "active_nodes": len(self.topology.nodes),
            "active_links": len(self.topology.links),
        })

    def handle_get_topology(self, req: HTTPRequest) -> HTTPResponse:
        return HTTPResponse.json(self.topology.to_dict())

    def handle_add_node(self, req: HTTPRequest) -> HTTPResponse:
        try:
            body = json.loads(req.body.decode("utf-8")) if req.body else {}
            node_id = body.get("id", f"node_{len(self.topology.nodes) + 1}")
            label = body.get("label", f"Host-{node_id}")
            node_type_str = body.get("type", "host").lower()
            type_map = {
                "router": NodeType.ROUTER,
                "switch": NodeType.SWITCH,
                "server": NodeType.SERVER,
                "host": NodeType.HOST,
                "firewall": NodeType.FIREWALL,
            }
            node_type = type_map.get(node_type_str, NodeType.HOST)
            x = body.get("x", 200 + (len(self.topology.nodes) * 50) % 500)
            y = body.get("y", 250 + (len(self.topology.nodes) * 30) % 200)

            node = self.topology.add_node(node_id, node_type, label, x, y)
            # If there's a switch, link to it
            switches = [n for n in self.topology.nodes.values() if n.node_type == NodeType.SWITCH]
            if switches:
                sw = switches[0]
                link_id = f"link_{node_id}_{sw.node_id}"
                self.topology.add_link(link_id, node_id, "eth0", sw.node_id, f"p{len(self.topology.links)+1}")

            return HTTPResponse.json({"success": True, "node_id": node_id, "label": label, "x": x, "y": y})
        except Exception as e:
            return HTTPResponse.json({"error": str(e)}, status_code=400)

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
        import random
        pps = round(1400.0 + random.uniform(-100.0, 150.0), 1)
        mbps = round((pps * 1500 * 8) / 1_000_000, 2)
        lat = round(1.2 + random.uniform(-0.3, 0.5), 2)
        return HTTPResponse.json({
            "pps": pps,
            "mbps": mbps,
            "drops_per_sec": 0.0,
            "latency_p50_ms": lat,
            "latency_p95_ms": round(lat * 2.8, 2),
            "latency_p99_ms": round(lat * 5.2, 2),
        })

    def handle_catalog_search(self, req: HTTPRequest) -> HTTPResponse:
        query = req.query_params.get("q", "").strip().lower()
        from netsphere.catalog.ports import PORT_DIRECTORY
        from netsphere.catalog.oui import OUI_DIRECTORY
        from netsphere.catalog.rfc import RFC_CATALOG

        results = []
        # Search ports
        count = 0
        for port, entry in PORT_DIRECTORY.items():
            if not query or query in str(port) or query in entry.service.lower() or query in entry.description.lower():
                results.append({
                    "type": "PORT",
                    "id": port,
                    "title": f"Port {port}/{entry.transport} - {entry.service}",
                    "detail": entry.description,
                    "rfc": entry.rfc,
                    "category": entry.category,
                })
                count += 1
                if count >= 30:
                    break

        # Search RFCs
        rfc_count = 0
        for num, entry in RFC_CATALOG.items():
            if query and (query in str(num) or query in entry.title.lower() or query in entry.abstract.lower()):
                results.append({
                    "type": "RFC",
                    "id": num,
                    "title": f"RFC {num}: {entry.title}",
                    "detail": entry.abstract,
                    "rfc": f"RFC {num}",
                    "category": entry.category,
                })
                rfc_count += 1
                if rfc_count >= 10:
                    break

        return HTTPResponse.json({"query": query, "count": len(results), "items": results})
