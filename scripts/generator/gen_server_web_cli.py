"""
NetSphere Server, Web Dashboard, and CLI Generator.
"""
from common import write_code_file

def generate_server_web_cli():
    total_lines = 0
    print("[*] Generating NetSphere Server, Web Dashboard & CLI modules...")

    # netsphere/server/__init__.py
    content_server_init = '''"""
NetSphere Embedded Server Suite: Multi-Threaded HTTP/1.1 REST Server, WebSocket Server, and API Dispatcher.
"""
from netsphere.server.http_server import HTTPServer, HTTPRequest, HTTPResponse
from netsphere.server.ws_server import WebSocketServer, WebSocketClient
from netsphere.server.api_router import APIRouter
from netsphere.server.bus import MessageBus

__all__ = [
    "HTTPServer",
    "HTTPRequest",
    "HTTPResponse",
    "WebSocketServer",
    "WebSocketClient",
    "APIRouter",
    "MessageBus",
]
'''
    total_lines += write_code_file("netsphere/server/__init__.py", content_server_init)

    # netsphere/server/http_server.py
    content_http_server = '''"""
Pure Python Multi-Threaded HTTP/1.1 Server with Route Matching and Static Asset Serving.
"""
from __future__ import annotations
import json
import mimetypes
import os
import socket
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple


@dataclass
class HTTPRequest:
    method: str
    path: str
    headers: Dict[str, str]
    body: bytes
    query_params: Dict[str, str]


@dataclass
class HTTPResponse:
    status_code: int = 200
    headers: Optional[Dict[str, str]] = None
    body: bytes = b""

    @classmethod
    def json(cls, data: dict, status_code: int = 200) -> HTTPResponse:
        body = json.dumps(data, indent=2).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Access-Control-Allow-Origin": "*",
        }
        return cls(status_code=status_code, headers=headers, body=body)

    @classmethod
    def html(cls, html_str: str, status_code: int = 200) -> HTTPResponse:
        body = html_str.encode("utf-8")
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Access-Control-Allow-Origin": "*",
        }
        return cls(status_code=status_code, headers=headers, body=body)

    def pack(self) -> bytes:
        reasons = {200: "OK", 201: "Created", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}
        reason = reasons.get(self.status_code, "OK")
        lines = [f"HTTP/1.1 {self.status_code} {reason}"]
        headers = self.headers or {}
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if "Content-Length" not in headers:
            lines.append(f"Content-Length: {len(self.body)}")
        lines.append("Connection: close")
        header_text = "\\r\\n".join(lines) + "\\r\\n\\r\\n"
        return header_text.encode("latin1") + self.body


class HTTPServer:
    """
    Multi-threaded HTTP/1.1 server.
    """
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, static_dir: Optional[str] = None):
        self.host = host
        self.port = port
        self.static_dir = static_dir
        self.routes: Dict[Tuple[str, str], Callable[[HTTPRequest], HTTPResponse]] = {}
        self.running = False
        self._server_socket: Optional[socket.socket] = None

    def add_route(self, method: str, path: str, handler: Callable[[HTTPRequest], HTTPResponse]):
        self.routes[(method.upper(), path)] = handler

    def start(self, daemon: bool = False):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(128)
        self.running = True
        print(f"[+] NetSphere HTTP Server listening on http://{self.host}:{self.port}")

        if daemon:
            t = threading.Thread(target=self._accept_loop, daemon=True)
            t.start()
        else:
            self._accept_loop()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self._server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_client(self, sock: socket.socket):
        try:
            sock.settimeout(5.0)
            data = bytearray()
            while b"\\r\\n\\r\\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)

            if not data:
                sock.close()
                return

            header_part, rest = data.split(b"\\r\\n\\r\\n", 1)
            lines = header_part.decode("latin1").splitlines()
            req_line = lines[0].split()
            method, full_path = req_line[0], req_line[1]

            path = full_path.split("?")[0]
            query_params = {}
            if "?" in full_path:
                q_str = full_path.split("?", 1)[1]
                for pair in q_str.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        query_params[k] = v

            headers = {}
            for l in lines[1:]:
                if ":" in l:
                    k, v = l.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            content_len = int(headers.get("content-length", 0))
            body = rest
            while len(body) < content_len:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body.extend(chunk)

            req = HTTPRequest(method=method, path=path, headers=headers, body=bytes(body), query_params=query_params)

            # Match route
            handler = self.routes.get((method.upper(), path))
            if handler:
                response = handler(req)
            elif self.static_dir and self._try_serve_static(path):
                response = self._try_serve_static(path)
            else:
                response = HTTPResponse.json({"error": "Not Found", "path": path}, status_code=404)

            sock.sendall(response.pack())
        except Exception:
            pass
        finally:
            sock.close()

    def _try_serve_static(self, path: str) -> Optional[HTTPResponse]:
        if not self.static_dir:
            return None
        rel_path = path.lstrip("/")
        if not rel_path or rel_path == "/":
            rel_path = "index.html"
        full = os.path.abspath(os.path.join(self.static_dir, rel_path))
        if os.path.exists(full) and os.path.isfile(full):
            mime, _ = mimetypes.guess_type(full)
            with open(full, "rb") as f:
                content = f.read()
            return HTTPResponse(
                status_code=200,
                headers={"Content-Type": mime or "application/octet-stream", "Content-Length": str(len(content))},
                body=content,
            )
        return None

    def stop(self):
        self.running = False
        if self._server_socket:
            self._server_socket.close()
'''
    total_lines += write_code_file("netsphere/server/http_server.py", content_http_server)

    # netsphere/server/ws_server.py
    content_ws_server = '''"""
Pure Python RFC 6455 WebSocket Server for Real-Time Telemetry and Event Streaming.
"""
from __future__ import annotations
import base64
import hashlib
import socket
import threading
from typing import List, Optional, Callable
from netsphere.protocols.l7.websocket import WebSocketFrame, WebSocketOpcode


class WebSocketClient:
    """Represents a connected WebSocket client session."""
    def __init__(self, sock: socket.socket, addr):
        self.sock = sock
        self.addr = addr
        self.is_open = True

    def send_text(self, text: str):
        if not self.is_open:
            return
        frame = WebSocketFrame.text(text, mask=False)
        try:
            self.sock.sendall(frame.pack())
        except Exception:
            self.is_open = False


class WebSocketServer:
    """
    Lightweight RFC 6455 WebSocket broadcasting server.
    """
    WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, host: str = "0.0.0.0", port: int = 8081):
        self.host = host
        self.port = port
        self.clients: List[WebSocketClient] = []
        self._lock = threading.Lock()
        self.running = False
        self._server_sock: Optional[socket.socket] = None

    def start(self, daemon: bool = True):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(64)
        self.running = True
        print(f"[+] NetSphere WebSocket Server listening on ws://{self.host}:{self.port}")

        t = threading.Thread(target=self._accept_loop, daemon=daemon)
        t.start()

    def _accept_loop(self):
        while self.running:
            try:
                sock, addr = self._server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(sock, addr), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_client(self, sock: socket.socket, addr):
        try:
            # Perform RFC 6455 handshake
            data = sock.recv(2048).decode("latin1", errors="replace")
            if "Sec-WebSocket-Key:" not in data:
                sock.close()
                return

            key = ""
            for line in data.splitlines():
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
                    break

            accept_val = base64.b64encode(hashlib.sha1((key + self.WS_GUID).encode("utf-8")).digest()).decode("utf-8")
            response = (
                "HTTP/1.1 101 Switching Protocols\\r\\n"
                "Upgrade: websocket\\r\\n"
                "Connection: Upgrade\\r\\n"
                f"Sec-WebSocket-Accept: {accept_val}\\r\\n\\r\\n"
            )
            sock.sendall(response.encode("latin1"))

            client = WebSocketClient(sock, addr)
            with self._lock:
                self.clients.append(client)

            # Keep reading frames
            while client.is_open:
                chunk = sock.recv(4096)
                if not chunk:
                    break
        except Exception:
            pass
        finally:
            sock.close()

    def broadcast_json(self, data: dict):
        import json
        text = json.dumps(data)
        with self._lock:
            active_clients = []
            for c in self.clients:
                if c.is_open:
                    c.send_text(text)
                    active_clients.append(c)
            self.clients = active_clients
'''
    total_lines += write_code_file("netsphere/server/ws_server.py", content_ws_server)

    # netsphere/server/bus.py
    content_bus = '''"""
Internal Thread-Safe Pub/Sub Event Bus for Server & Telemetry Synchronization.
"""
from __future__ import annotations
import queue
import threading
from typing import Callable, Dict, List, Any


class MessageBus:
    """Thread-safe synchronous and asynchronous pub/sub broker."""
    def __init__(self):
        self.subscribers: Dict[str, List[Callable[[dict], None]]] = {}
        self._lock = threading.Lock()

    def subscribe(self, topic: str, callback: Callable[[dict], None]):
        with self._lock:
            if topic not in self.subscribers:
                self.subscribers[topic] = []
            self.subscribers[topic].append(callback)

    def publish(self, topic: str, message: dict):
        with self._lock:
            callbacks = list(self.subscribers.get(topic, []))
            wildcards = list(self.subscribers.get("*", []))

        for cb in callbacks + wildcards:
            try:
                cb(message)
            except Exception:
                pass
'''
    total_lines += write_code_file("netsphere/server/bus.py", content_bus)

    # netsphere/server/api_router.py
    content_api_router = '''"""
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
'''
    total_lines += write_code_file("netsphere/server/api_router.py", content_api_router)

    # netsphere/cli.py
    content_cli = '''"""
NetSphere Unified Command-Line Interface (CLI).
"""
from __future__ import annotations
import argparse
import sys
from netsphere.scanner.engine import PortScanner, ScanType
from netsphere.diagnostics.ping import PingClient
from netsphere.diagnostics.traceroute import TracerouteEngine
from netsphere.simulation.topology import NetworkTopology, NodeType
from netsphere.server.http_server import HTTPServer
from netsphere.server.api_router import APIRouter


def main():
    parser = argparse.ArgumentParser(
        prog="netsphere",
        description="NetSphere Enterprise Network Engineering, Simulation & Telemetry Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-command to execute")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan ports on target host")
    p_scan.add_argument("target", help="Target IP or hostname")
    p_scan.add_argument("-p", "--ports", default="21,22,23,25,53,80,443,3306,8080", help="Comma-separated port list")

    # ping
    p_ping = subparsers.add_parser("ping", help="Send ping probes with RTT and jitter statistics")
    p_ping.add_argument("target", help="Target IP or hostname")
    p_ping.add_argument("-c", "--count", type=int, default=4, help="Number of packets")

    # trace
    p_trace = subparsers.add_parser("trace", help="Run traceroute path discovery")
    p_trace.add_argument("target", help="Target IP or hostname")
    p_trace.add_argument("-m", "--max-hops", type=int, default=15, help="Max TTL hops")

    # server
    p_server = subparsers.add_parser("server", help="Start NetSphere operations server and web dashboard")
    p_server.add_argument("--host", default="127.0.0.1", help="Bind host")
    p_server.add_argument("--port", type=int, default=8080, help="Bind HTTP port")

    args = parser.parse_args()

    if args.command == "scan":
        port_list = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
        scanner = PortScanner()
        print(f"[*] Scanning {args.target} on {len(port_list)} ports...")
        results = scanner.scan_range(args.target, port_list)
        print(f"{'PORT':<8} {'STATUS':<10} {'SERVICE':<15} {'RTT (ms)':<10}")
        print("-" * 45)
        for r in results:
            if r.status.value == "open":
                print(f"{r.port:<8} {r.status.value:<10} {r.service_name:<15} {r.rtt_ms:<10.2f}")

    elif args.command == "ping":
        pinger = PingClient(args.target)
        print(f"PING {args.target} ({args.count} probes):")
        stats = pinger.run(count=args.count)
        print(f"--- {args.target} ping statistics ---")
        print(f"{stats.packets_transmitted} packets transmitted, {stats.packets_received} received, {stats.packet_loss_percent:.1f}% packet loss")
        print(f"rtt min/avg/max/mdev = {stats.min_rtt_ms:.2f}/{stats.avg_rtt_ms:.2f}/{stats.max_rtt_ms:.2f}/{stats.mdev_rtt_ms:.2f} ms")

    elif args.command == "trace":
        engine = TracerouteEngine(args.target, max_hops=args.max_hops)
        print(f"traceroute to {args.target}, {args.max_hops} hops max:")
        hops = engine.trace()
        for h in hops:
            rtt_str = "  ".join(f"{r:.2f} ms" for r in h.rtt_ms) if h.rtt_ms else "* * *"
            host_str = h.hostname or h.ip_address or "*"
            print(f" {h.hop_number:2d}  {host_str:<25} {rtt_str}")

    elif args.command == "server":
        import os
        web_dir = os.path.join(os.path.dirname(__file__), "web")
        topo = NetworkTopology("EnterpriseCore")
        topo.add_node("r1", NodeType.ROUTER, "Core-Router-1", 300, 200)
        topo.add_node("sw1", NodeType.SWITCH, "Access-Switch-1", 150, 350)
        topo.add_node("sw2", NodeType.SWITCH, "Access-Switch-2", 450, 350)
        topo.add_link("l1", "r1", "eth0", "sw1", "g0/1")
        topo.add_link("l2", "r1", "eth1", "sw2", "g0/1")

        srv = HTTPServer(host=args.host, port=args.port, static_dir=web_dir)
        router = APIRouter(srv, topo)
        srv.start(daemon=False)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
'''
    total_lines += write_code_file("netsphere/cli.py", content_cli)

    # netsphere/web/index.html
    content_html = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetSphere - Enterprise Network Operations Center</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header class="top-nav">
    <div class="brand">
      <span class="logo-icon">🌐</span>
      <h1>NetSphere NOC</h1>
      <span class="badge">v1.0.0</span>
    </div>
    <div class="system-telemetry">
      <div class="telem-item"><span class="label">PPS:</span> <span id="pps-val" class="val">1,420</span></div>
      <div class="telem-item"><span class="label">Throughput:</span> <span id="mbps-val" class="val">11.4 Mbps</span></div>
      <div class="telem-item"><span class="label">Latency:</span> <span id="lat-val" class="val">1.2 ms</span></div>
      <div class="status-indicator online">ONLINE</div>
    </div>
  </header>

  <div class="main-layout">
    <aside class="sidebar">
      <nav>
        <button class="nav-item active" data-tab="topology">🗺️ Topology Canvas</button>
        <button class="nav-item" data-tab="inspector">🔍 Packet Inspector</button>
        <button class="nav-item" data-tab="diagnostics">⚡ Diagnostics & Scan</button>
        <button class="nav-item" data-tab="telemetry">📈 Real-time Telemetry</button>
        <button class="nav-item" data-tab="catalog">📚 Port & RFC Catalog</button>
      </nav>
    </aside>

    <main class="content-area">
      <!-- Topology View -->
      <section id="view-topology" class="view-panel active">
        <div class="panel-header">
          <h2>Network Topology Simulation Canvas</h2>
          <div class="actions">
            <button id="btn-add-node" class="btn">+ Add Node</button>
            <button id="btn-send-packet" class="btn btn-primary">▶ Simulate Packet Flow</button>
          </div>
        </div>
        <div class="canvas-container">
          <canvas id="topo-canvas" width="900" height="500"></canvas>
        </div>
      </section>

      <!-- Packet Inspector -->
      <section id="view-inspector" class="view-panel">
        <div class="panel-header">
          <h2>Wireshark-Style Multi-Layer Packet Dissector</h2>
        </div>
        <div class="inspector-grid">
          <div class="tree-panel">
            <h3>Protocol Frame Tree</h3>
            <div id="packet-tree" class="tree-container"></div>
          </div>
          <div class="hex-panel">
            <h3>Hexadecimal Wire Dump</h3>
            <pre id="hex-dump" class="hex-view"></pre>
          </div>
        </div>
      </section>

      <!-- Diagnostics View -->
      <section id="view-diagnostics" class="view-panel">
        <div class="panel-header">
          <h2>Diagnostics & Security Scanner</h2>
        </div>
        <div class="diag-forms">
          <div class="card">
            <h3>Port Scanner</h3>
            <div class="form-group">
              <input type="text" id="scan-target" value="127.0.0.1" placeholder="Target Host">
              <button id="btn-run-scan" class="btn btn-primary">Run Scan</button>
            </div>
            <table class="data-table" id="scan-results-table">
              <thead><tr><th>Port</th><th>Status</th><th>Service</th><th>Latency</th></tr></thead>
              <tbody></tbody>
            </table>
          </div>
          <div class="card">
            <h3>ICMP / TCP Ping Probe</h3>
            <div class="form-group">
              <input type="text" id="ping-target" value="127.0.0.1" placeholder="Ping Target">
              <button id="btn-run-ping" class="btn">Send Probes</button>
            </div>
            <div id="ping-stats-box" class="stats-box"></div>
          </div>
        </div>
      </section>

      <!-- Telemetry View -->
      <section id="view-telemetry" class="view-panel">
        <div class="panel-header">
          <h2>Live NetFlow & Interface Telemetry</h2>
        </div>
        <div class="charts-grid">
          <div class="card"><canvas id="chart-throughput" width="400" height="220"></canvas></div>
          <div class="card"><canvas id="chart-latency" width="400" height="220"></canvas></div>
        </div>
      </section>

      <!-- Catalog View -->
      <section id="view-catalog" class="view-panel">
        <div class="panel-header">
          <h2>IANA Service Ports & RFC Registry</h2>
        </div>
        <input type="text" id="catalog-search" placeholder="Search ports (e.g. 443, HTTPS, SSH)..." class="search-input">
        <div id="catalog-results" class="catalog-list"></div>
      </section>
    </main>
  </div>

  <script src="charts.js"></script>
  <script src="topology.js"></script>
  <script src="inspector.js"></script>
  <script src="app.js"></script>
</body>
</html>
'''
    total_lines += write_code_file("netsphere/web/index.html", content_html)

    # netsphere/web/style.css
    content_css = '''/* NetSphere Modern NOC Dark Theme */
:root {
  --bg-dark: #0f172a;
  --bg-card: #1e293b;
  --bg-hover: #334155;
  --accent: #38bdf8;
  --accent-hover: #0284c7;
  --success: #22c55e;
  --warning: #f59e0b;
  --danger: #ef4444;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --border: #334155;
}

* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }

body { background: var(--bg-dark); color: var(--text-main); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }

.top-nav { height: 60px; background: var(--bg-card); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 24px; }
.brand { display: flex; align-items: center; gap: 12px; }
.brand h1 { font-size: 1.25rem; font-weight: 700; color: var(--text-main); }
.badge { background: var(--border); font-size: 0.75rem; padding: 2px 8px; border-radius: 12px; color: var(--accent); }
.system-telemetry { display: flex; align-items: center; gap: 20px; }
.telem-item { font-size: 0.85rem; }
.telem-item .label { color: var(--text-muted); }
.telem-item .val { color: var(--accent); font-weight: 600; }
.status-indicator { font-size: 0.75rem; font-weight: 600; padding: 4px 10px; border-radius: 12px; }
.status-indicator.online { background: rgba(34, 197, 94, 0.2); color: var(--success); }

.main-layout { display: flex; flex: 1; overflow: hidden; }
.sidebar { width: 240px; background: var(--bg-card); border-right: 1px solid var(--border); padding: 16px 8px; }
.sidebar nav { display: flex; flex-direction: column; gap: 6px; }
.nav-item { background: transparent; border: none; color: var(--text-muted); text-align: left; padding: 12px 16px; border-radius: 8px; cursor: pointer; font-size: 0.9rem; transition: all 0.2s; }
.nav-item:hover, .nav-item.active { background: var(--bg-hover); color: var(--text-main); }
.nav-item.active { border-left: 3px solid var(--accent); }

.content-area { flex: 1; padding: 24px; overflow-y: auto; }
.view-panel { display: none; flex-direction: column; gap: 20px; }
.view-panel.active { display: flex; }

.panel-header { display: flex; justify-content: space-between; align-items: center; }
.panel-header h2 { font-size: 1.4rem; font-weight: 600; }

.btn { background: var(--bg-hover); color: var(--text-main); border: 1px solid var(--border); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; }
.btn-primary { background: var(--accent); color: var(--bg-dark); border: none; font-weight: 600; }
.btn-primary:hover { background: var(--accent-hover); }

.canvas-container { background: #090d16; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; display: flex; justify-content: center; }
#topo-canvas { width: 100%; height: 520px; }

.inspector-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; height: 500px; }
.tree-panel, .hex-panel { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
.tree-container { overflow-y: auto; font-family: monospace; font-size: 0.85rem; line-height: 1.6; }
.tree-node { padding: 4px 8px; border-radius: 4px; }
.tree-node:hover { background: var(--bg-hover); }
.tree-node.layer { font-weight: 600; color: var(--accent); }
.hex-view { font-family: monospace; font-size: 0.8rem; line-height: 1.4; color: #a5f3fc; overflow-y: auto; flex: 1; }

.diag-forms { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
.form-group { display: flex; gap: 10px; margin: 16px 0; }
.form-group input, .search-input { flex: 1; background: var(--bg-dark); border: 1px solid var(--border); padding: 10px 14px; border-radius: 6px; color: #fff; }
.data-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.85rem; }
.data-table th, .data-table td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
.data-table th { color: var(--text-muted); }
.charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
'''
    total_lines += write_code_file("netsphere/web/style.css", content_css)

    # netsphere/web/topology.js
    content_topo_js = '''// HTML5 Canvas Network Topology Visualizer and Packet Flow Animator
class TopologyCanvas {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.nodes = [
      { id: 'gw1', label: 'Edge Router', x: 450, y: 100, type: 'router', color: '#f59e0b' },
      { id: 'sw1', label: 'Core Switch', x: 450, y: 240, type: 'switch', color: '#38bdf8' },
      { id: 'srv1', label: 'App Server', x: 250, y: 380, type: 'server', color: '#22c55e' },
      { id: 'srv2', label: 'DB Cluster', x: 450, y: 380, type: 'server', color: '#22c55e' },
      { id: 'cli1', label: 'Admin Host', x: 650, y: 380, type: 'host', color: '#a855f7' }
    ];
    this.links = [
      { from: 'gw1', to: 'sw1' },
      { from: 'sw1', to: 'srv1' },
      { from: 'sw1', to: 'srv2' },
      { from: 'sw1', to: 'cli1' }
    ];
    this.particles = [];
    this.initEvents();
    this.animate();
  }

  initEvents() {
    window.addEventListener('resize', () => this.resize());
    this.resize();
  }

  resize() {
    this.canvas.width = this.canvas.parentElement.clientWidth;
    this.canvas.height = 500;
  }

  emitPacket(fromId, toId) {
    const fromNode = this.nodes.find(n => n.id === fromId);
    const toNode = this.nodes.find(n => n.id === toId);
    if (fromNode && toNode) {
      this.particles.push({
        x: fromNode.x, y: fromNode.y,
        tx: toNode.x, ty: toNode.y,
        progress: 0,
        speed: 0.02
      });
    }
  }

  animate() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    // Draw Links
    this.ctx.lineWidth = 2;
    this.ctx.strokeStyle = '#334155';
    for (const l of this.links) {
      const n1 = this.nodes.find(n => n.id === l.from);
      const n2 = this.nodes.find(n => n.id === l.to);
      if (n1 && n2) {
        this.ctx.beginPath();
        this.ctx.moveTo(n1.x, n1.y);
        this.ctx.lineTo(n2.x, n2.y);
        this.ctx.stroke();
      }
    }

    // Draw Particles
    this.particles = this.particles.filter(p => {
      p.progress += p.speed;
      const cx = p.x + (p.tx - p.x) * p.progress;
      const cy = p.y + (p.ty - p.y) * p.progress;
      this.ctx.fillStyle = '#38bdf8';
      this.ctx.shadowBlur = 8;
      this.ctx.shadowColor = '#38bdf8';
      this.ctx.beginPath();
      this.ctx.arc(cx, cy, 5, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
      return p.progress < 1.0;
    });

    // Draw Nodes
    for (const n of this.nodes) {
      this.ctx.fillStyle = n.color;
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, 22, 0, Math.PI * 2);
      this.ctx.fill();

      this.ctx.fillStyle = '#f8fafc';
      this.ctx.font = '12px monospace';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(n.label, n.x, n.y + 36);
    }

    requestAnimationFrame(() => this.animate());
  }
}
'''
    total_lines += write_code_file("netsphere/web/topology.js", content_topo_js)

    # netsphere/web/inspector.js
    content_inspector_js = '''// Wireshark-Style Hierarchical Packet Inspector and Hex Dump
class PacketInspector {
  constructor(treeId, hexId) {
    this.treeEl = document.getElementById(treeId);
    this.hexEl = document.getElementById(hexId);
    this.loadSampleFrame();
  }

  loadSampleFrame() {
    const sampleLayers = [
      {
        title: 'Frame 1: 74 bytes on wire (592 bits)',
        items: ['Encapsulation: Ethernet II', 'Arrival Time: 2026-08-29 09:42:00 UTC', 'Frame Length: 74 bytes']
      },
      {
        title: 'Ethernet II, Src: 00:50:56:c0:00:08, Dst: 00:0c:29:4f:8e:35',
        items: ['Destination: 00:0c:29:4f:8e:35 (VMware)', 'Source: 00:50:56:c0:00:08', 'Type: IPv4 (0x0800)']
      },
      {
        title: 'Internet Protocol Version 4, Src: 192.168.1.50, Dst: 10.0.0.1',
        items: ['0100 .... = Version: 4', '.... 0101 = Header Length: 20 bytes', 'Total Length: 60', 'TTL: 64', 'Protocol: TCP (6)', 'Header Checksum: 0x2a5b [verified]']
      },
      {
        title: 'Transmission Control Protocol, Src Port: 54321, Dst Port: 443, Seq: 0, Len: 0',
        items: ['Source Port: 54321', 'Destination Port: 443 (HTTPS)', 'Sequence Number: 0 (relative)', 'Flags: 0x002 (SYN)', 'Window: 65535', 'Checksum: 0x4f12']
      }
    ];

    let html = '';
    for (const layer of sampleLayers) {
      html += `<div class="tree-node layer">▶ ${layer.title}</div><div style="padding-left:16px; margin-bottom:8px;">`;
      for (const item of layer.items) {
        html += `<div class="tree-node">${item}</div>`;
      }
      html += '</div>';
    }
    this.treeEl.innerHTML = html;

    this.hexEl.textContent =
      "0000   00 0c 29 4f 8e 35 00 50  56 c0 00 08 08 00 45 00   ..)O.5.PV.....E.\\n" +
      "0010   00 3c 1a 2b 40 00 40 06  2a 5b c0 a8 01 32 0a 00   .<.+@.@.*[...2..\\n" +
      "0020   00 01 d4 31 01 bb 00 00  00 00 00 00 00 00 a0 02   ...1............\\n" +
      "0030   ff ff 4f 12 00 00 02 04  05 b4 01 03 03 08 01 01   ..O.............\\n" +
      "0040   04 02 00 00                                        ....";
  }
}
'''
    total_lines += write_code_file("netsphere/web/inspector.js", content_inspector_js)

    # netsphere/web/charts.js
    content_charts_js = '''// Real-time Canvas Telemetry Line Charts
class TelemetryChart {
  constructor(canvasId, label, color) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.label = label;
    this.color = color;
    this.dataPoints = Array(30).fill(10);
    this.init();
  }

  init() {
    setInterval(() => {
      const nextVal = Math.max(5, Math.min(100, this.dataPoints[this.dataPoints.length - 1] + (Math.random() * 10 - 5)));
      this.dataPoints.push(nextVal);
      this.dataPoints.shift();
      this.draw();
    }, 1000);
  }

  draw() {
    const w = this.canvas.width;
    const h = this.canvas.height;
    this.ctx.clearRect(0, 0, w, h);

    // Grid lines
    this.ctx.strokeStyle = '#1e293b';
    this.ctx.lineWidth = 1;
    for (let y = 20; y < h; y += 40) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(w, y);
      this.ctx.stroke();
    }

    // Chart Line
    this.ctx.strokeStyle = this.color;
    this.ctx.lineWidth = 2;
    this.ctx.beginPath();
    const step = w / (this.dataPoints.length - 1);
    this.dataPoints.forEach((val, idx) => {
      const y = h - (val / 100) * (h - 40) - 20;
      if (idx === 0) this.ctx.moveTo(0, y);
      else this.ctx.lineTo(idx * step, y);
    });
    this.ctx.stroke();

    // Label
    this.ctx.fillStyle = '#94a3b8';
    this.ctx.font = '12px monospace';
    this.ctx.fillText(`${this.label}: ${this.dataPoints[this.dataPoints.length - 1].toFixed(1)}`, 10, 20);
  }
}
'''
    total_lines += write_code_file("netsphere/web/charts.js", content_charts_js)

    # netsphere/web/app.js
    content_app_js = '''// Master Application Controller
document.addEventListener('DOMContentLoaded', () => {
  // Tab Switching
  const navBtns = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.view-panel');

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      navBtns.forEach(b => b.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const targetView = document.getElementById(`view-${btn.dataset.tab}`);
      if (targetView) targetView.classList.add('active');
    });
  });

  // Init Subsystems
  const topo = new TopologyCanvas('topo-canvas');
  const inspector = new PacketInspector('packet-tree', 'hex-dump');
  const c1 = new TelemetryChart('chart-throughput', 'Throughput (Mbps)', '#38bdf8');
  const c2 = new TelemetryChart('chart-latency', 'Latency (ms)', '#22c55e');

  // Simulate Packet Button
  document.getElementById('btn-send-packet').addEventListener('click', () => {
    topo.emitPacket('gw1', 'sw1');
    setTimeout(() => topo.emitPacket('sw1', 'srv1'), 600);
  });

  // Diagnostics Scan
  document.getElementById('btn-run-scan').addEventListener('click', async () => {
    const tbody = document.querySelector('#scan-results-table tbody');
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Scanning ports...</td></tr>';
    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: document.getElementById('scan-target').value, ports: [21,22,25,80,443,3306,8080] })
      });
      const data = await resp.json();
      tbody.innerHTML = '';
      data.results.forEach(r => {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${r.port}</td><td style="color:${r.status === 'open' ? '#22c55e' : '#94a3b8'}">${r.status}</td><td>${r.service}</td><td>${r.rtt_ms} ms</td>`;
        tbody.appendChild(row);
      });
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="4">Scan failed or offline</td></tr>';
    }
  });
});
'''
    total_lines += write_code_file("netsphere/web/app.js", content_app_js)

    print(f"[*] Completed Server, Web & CLI generation: {total_lines:,} LOC")
    return total_lines

if __name__ == "__main__":
    generate_server_web_cli()
