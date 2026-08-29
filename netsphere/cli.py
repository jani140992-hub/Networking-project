"""
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
