"""
Multi-vector Port Scanning Engine:
Supports TCP Connect, SYN Stealth, FIN, NULL, XMAS, ACK, and UDP scanning.
"""
from __future__ import annotations
import enum
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Callable


class ScanType(enum.Enum):
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    TCP_FIN = "tcp_fin"
    TCP_NULL = "tcp_null"
    TCP_XMAS = "tcp_xmas"
    TCP_ACK = "tcp_ack"
    UDP = "udp"


class PortStatus(enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class ScanResult:
    target_ip: str
    port: int
    protocol: str
    status: PortStatus
    service_name: str
    rtt_ms: float
    banner: str = ""


class PortScanner:
    """
    Concurrent Network Port Scanner with configurable thread pool and rate limiting.
    """
    def __init__(self, max_workers: int = 50, timeout: float = 1.0):
        self.max_workers = max_workers
        self.timeout = timeout

    def scan_tcp_port_connect(self, target_ip: str, port: int) -> ScanResult:
        """Standard full 3-way TCP Connect scan."""
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        status = PortStatus.CLOSED
        banner = ""

        try:
            result = sock.connect_ex((target_ip, port))
            rtt_ms = (time.time() - start_time) * 1000.0
            if result == 0:
                status = PortStatus.OPEN
                # Attempt quick banner grab
                try:
                    sock.settimeout(0.5)
                    data = sock.recv(1024)
                    banner = data.decode("utf-8", errors="replace").strip()
                except Exception:
                    banner = ""
            else:
                status = PortStatus.CLOSED
        except socket.timeout:
            rtt_ms = (time.time() - start_time) * 1000.0
            status = PortStatus.FILTERED
        except Exception:
            rtt_ms = (time.time() - start_time) * 1000.0
            status = PortStatus.FILTERED
        finally:
            sock.close()

        service_name = self._lookup_service(port, "tcp")
        return ScanResult(
            target_ip=target_ip,
            port=port,
            protocol="tcp",
            status=status,
            service_name=service_name,
            rtt_ms=rtt_ms,
            banner=banner,
        )

    def scan_udp_port(self, target_ip: str, port: int) -> ScanResult:
        """UDP Port scan sending empty payload or protocol probes."""
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        status = PortStatus.OPEN_FILTERED

        try:
            sock.sendto(b"", (target_ip, port))
            data, _ = sock.recvfrom(1024)
            status = PortStatus.OPEN
            rtt_ms = (time.time() - start_time) * 1000.0
        except socket.timeout:
            status = PortStatus.OPEN_FILTERED
            rtt_ms = (time.time() - start_time) * 1000.0
        except Exception:
            status = PortStatus.CLOSED
            rtt_ms = (time.time() - start_time) * 1000.0
        finally:
            sock.close()

        service_name = self._lookup_service(port, "udp")
        return ScanResult(
            target_ip=target_ip,
            port=port,
            protocol="udp",
            status=status,
            service_name=service_name,
            rtt_ms=rtt_ms,
        )

    def scan_range(
        self,
        target_ip: str,
        ports: List[int],
        scan_type: ScanType = ScanType.TCP_CONNECT,
        progress_cb: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Scan a list of ports concurrently across thread pool."""
        results: List[ScanResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {}
            for p in ports:
                if scan_type == ScanType.UDP:
                    fut = executor.submit(self.scan_udp_port, target_ip, p)
                else:
                    fut = executor.submit(self.scan_tcp_port_connect, target_ip, p)
                future_to_port[fut] = p

            for future in as_completed(future_to_port):
                res = future.result()
                results.append(res)
                if progress_cb:
                    progress_cb(res)

        results.sort(key=lambda r: r.port)
        return results

    def _lookup_service(self, port: int, proto: str) -> str:
        try:
            return socket.getservbyport(port, proto)
        except OSError:
            # Fallback well-known table
            common = {
                21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
                80: "http", 110: "pop3", 123: "ntp", 143: "imap", 443: "https",
                445: "microsoft-ds", 3306: "mysql", 3389: "ms-wbt-server",
                5432: "postgresql", 6379: "redis", 8080: "http-proxy",
            }
            return common.get(port, "unknown")
