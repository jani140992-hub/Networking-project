"""
NetSphere Top-Level Application Entry Point.
Provides unified entry to the server, CLI, simulation, and tests.
"""
from __future__ import annotations
import argparse
import sys
import os

# Ensure package path is configured
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from netsphere.cli import main as cli_main
from netsphere.simulation.topology import NetworkTopology, NodeType
from netsphere.server.http_server import HTTPServer
from netsphere.server.api_router import APIRouter


def run_app(host: str = "127.0.0.1", port: int = 8080):
    """Start NetSphere Operations Center."""
    print("=" * 70)
    print("  NETSPHERE ENTERPRISE NETWORK OPERATIONS & TELEMETRY PLATFORM")
    print("=" * 70)
    web_dir = os.path.join(os.path.dirname(__file__), "netsphere", "web")
    topo = NetworkTopology("EnterpriseCore")
    topo.add_node("r1", NodeType.ROUTER, "Core-Router-1", 450, 80)
    topo.add_node("sw1", NodeType.SWITCH, "Core-Switch-1", 450, 220)
    topo.add_node("srv1", NodeType.SERVER, "App-Server-1", 220, 380)
    topo.add_node("srv2", NodeType.SERVER, "DB-Cluster-1", 450, 380)
    topo.add_node("cli1", NodeType.HOST, "Admin-Host-1", 680, 380)
    topo.add_link("l1", "r1", "eth0", "sw1", "g0/1")
    topo.add_link("l2", "sw1", "g0/2", "srv1", "eth0")
    topo.add_link("l3", "sw1", "g0/3", "srv2", "eth0")
    topo.add_link("l4", "sw1", "g0/4", "cli1", "eth0")

    server = HTTPServer(host=host, port=port, static_dir=web_dir)
    APIRouter(server, topo)
    server.start(daemon=False)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("scan", "ping", "trace", "sim", "catalog"):
        cli_main()
    else:
        parser = argparse.ArgumentParser(description="NetSphere Platform Launcher")
        parser.add_argument("--host", default="127.0.0.1", help="Binding host")
        parser.add_argument("--port", type=int, default=8080, help="Binding port")
        parser.add_argument("--demo", action="store_true", help="Run interactive demo")
        parser.add_argument("--test", action="store_true", help="Run automated test suite")
        args, unknown = parser.parse_known_args()

        if args.demo:
            from scripts.run_demo import run_demo
            run_demo()
        elif args.test:
            import unittest
            suite = unittest.defaultTestLoader.discover("tests")
            runner = unittest.TextTestRunner(verbosity=2)
            runner.run(suite)
        else:
            run_app(host=args.host, port=args.port)
