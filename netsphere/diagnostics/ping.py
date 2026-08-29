"""
High-Precision Ping Client with Latency, Jitter, and Packet Loss Statistics.
"""
from __future__ import annotations
import math
import socket
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class PingProbe:
    sequence: int
    rtt_ms: float
    success: bool
    error_msg: str = ""


@dataclass
class PingStatistics:
    target: str
    packets_transmitted: int
    packets_received: int
    packet_loss_percent: float
    min_rtt_ms: float
    avg_rtt_ms: float
    max_rtt_ms: float
    mdev_rtt_ms: float  # Standard deviation
    jitter_ms: float    # RFC 3550 interarrival jitter


class PingClient:
    """
    High precision Ping client. Uses socket connection probes when unprivileged.
    """
    def __init__(self, target: str, port: int = 80, timeout: float = 2.0):
        self.target = target
        self.port = port
        self.timeout = timeout

    def send_probe(self, sequence: int) -> PingProbe:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.target, self.port))
            rtt = (time.perf_counter() - start) * 1000.0
            return PingProbe(sequence=sequence, rtt_ms=rtt, success=True)
        except socket.timeout:
            return PingProbe(sequence=sequence, rtt_ms=0.0, success=False, error_msg="Request timeout")
        except Exception as e:
            return PingProbe(sequence=sequence, rtt_ms=0.0, success=False, error_msg=str(e))
        finally:
            sock.close()

    def run(self, count: int = 4, interval: float = 0.5) -> PingStatistics:
        probes: List[PingProbe] = []
        for i in range(count):
            probe = self.send_probe(sequence=i + 1)
            probes.append(probe)
            if i < count - 1:
                time.sleep(interval)

        successes = [p for p in probes if p.success]
        rtts = [p.rtt_ms for p in successes]

        tx = count
        rx = len(successes)
        loss = ((tx - rx) / tx) * 100.0 if tx > 0 else 0.0

        if rtts:
            min_rtt = min(rtts)
            max_rtt = max(rtts)
            avg_rtt = sum(rtts) / len(rtts)
            variance = sum((x - avg_rtt) ** 2 for x in rtts) / len(rtts)
            mdev = math.sqrt(variance)

            # Calculate RFC 3550 interarrival jitter
            jitter = 0.0
            for k in range(len(rtts) - 1):
                d = abs(rtts[k + 1] - rtts[k])
                jitter += (d - jitter) / 16.0
        else:
            min_rtt = avg_rtt = max_rtt = mdev = jitter = 0.0

        return PingStatistics(
            target=self.target,
            packets_transmitted=tx,
            packets_received=rx,
            packet_loss_percent=loss,
            min_rtt_ms=min_rtt,
            avg_rtt_ms=avg_rtt,
            max_rtt_ms=max_rtt,
            mdev_rtt_ms=mdev,
            jitter_ms=jitter,
        )
