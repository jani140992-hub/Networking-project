"""
Network Bandwidth & Throughput Benchmarking (iPerf-style TCP/UDP client & server).
"""
from __future__ import annotations
import socket
import time
import threading
from dataclasses import dataclass
from typing import Optional


@dataclass
class BenchmarkResult:
    protocol: str
    duration_sec: float
    bytes_transferred: int
    throughput_mbps: float
    retransmissions: int = 0
    packet_loss_percent: float = 0.0


class BandwidthBenchmark:
    """
    Throughput measurement utility.
    """
    def run_client(self, host: str, port: int = 5201, duration_sec: float = 5.0, buffer_size: int = 65536) -> BenchmarkResult:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        chunk = b"\xaa" * buffer_size
        total_bytes = 0
        start_time = time.time()

        try:
            sock.connect((host, port))
            end_time = start_time + duration_sec
            while time.time() < end_time:
                sock.sendall(chunk)
                total_bytes += len(chunk)
        except Exception:
            pass
        finally:
            sock.close()

        elapsed = max(0.001, time.time() - start_time)
        throughput_mbps = (total_bytes * 8.0) / (elapsed * 1_000_000.0)

        return BenchmarkResult(
            protocol="TCP",
            duration_sec=elapsed,
            bytes_transferred=total_bytes,
            throughput_mbps=throughput_mbps,
        )
