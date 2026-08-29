"""
High-Performance Time-Series Telemetry Metrics Engine.
Tracks packet rate, byte throughput, latency histograms, and percentiles.
"""
from __future__ import annotations
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Tuple, Deque


@dataclass
class MetricPoint:
    timestamp: float
    value: float


class RollingRateCounter:
    """Calculates rates (e.g. packets per second, bytes per second) over a sliding time window."""
    def __init__(self, window_seconds: float = 10.0):
        self.window = window_seconds
        self.samples: Deque[Tuple[float, float]] = deque()

    def add(self, value: float = 1.0, timestamp: Optional[float] = None) -> None:
        now = timestamp or time.time()
        self.samples.append((now, value))
        self._evict_old(now)

    def _evict_old(self, current_time: float) -> None:
        cutoff = current_time - self.window
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def get_rate(self, current_time: Optional[float] = None) -> float:
        now = current_time or time.time()
        self._evict_old(now)
        if not self.samples:
            return 0.0
        total_val = sum(val for _, val in self.samples)
        return total_val / self.window


class TelemetryMetricsEngine:
    """
    Central telemetry metrics engine collecting time-series operational metrics.
    """
    def __init__(self):
        self.pps_counter = RollingRateCounter(window_seconds=10.0)
        self.bps_counter = RollingRateCounter(window_seconds=10.0)
        self.drop_counter = RollingRateCounter(window_seconds=10.0)
        self.latency_samples: Deque[float] = deque(maxlen=500)

    def record_packet(self, packet_bytes: int, latency_ms: float = 1.0):
        self.pps_counter.add(1.0)
        self.bps_counter.add(packet_bytes * 8.0)
        self.latency_samples.append(latency_ms)

    def record_drop(self):
        self.drop_counter.add(1.0)

    def get_snapshot(self) -> Dict[str, float]:
        lats = sorted(self.latency_samples)
        p50 = lats[len(lats) // 2] if lats else 0.0
        p95 = lats[int(len(lats) * 0.95)] if lats else 0.0
        p99 = lats[int(len(lats) * 0.99)] if lats else 0.0

        return {
            "pps": self.pps_counter.get_rate(),
            "bps": self.bps_counter.get_rate(),
            "mbps": self.bps_counter.get_rate() / 1_000_000.0,
            "drops_per_sec": self.drop_counter.get_rate(),
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
            "latency_p99_ms": p99,
        }
