"""
Quality of Service (QoS), Traffic Shaping, and Buffer Management:
- Token Bucket Filter (TBF)
- Leaky Bucket
- Priority Queuing (PQ)
- Weighted Fair Queuing (WFQ)
- Random Early Detection (RED)
"""
from __future__ import annotations
import random
import time
from collections import deque
from dataclasses import dataclass
from typing import List, Optional, Tuple, Deque


class TokenBucketFilter:
    """
    Token Bucket Traffic Shaper (RFC 2697):
    - Capacity (Burst size in bytes)
    - Rate (Tokens per second in bytes/sec)
    """
    def __init__(self, rate_bytes_sec: float, burst_bytes: int):
        self.rate = rate_bytes_sec
        self.capacity = burst_bytes
        self.tokens: float = float(burst_bytes)
        self.last_update: float = time.time()

    def update(self) -> None:
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.rate)

    def consume(self, packet_bytes: int) -> bool:
        self.update()
        if self.tokens >= packet_bytes:
            self.tokens -= packet_bytes
            return True
        return False


class LeakyBucketFilter:
    """
    Leaky Bucket Traffic Policer:
    Enforces a constant outflow rate.
    """
    def __init__(self, leak_rate_bytes_sec: float, bucket_capacity_bytes: int):
        self.leak_rate = leak_rate_bytes_sec
        self.capacity = bucket_capacity_bytes
        self.current_fill: float = 0.0
        self.last_leak: float = time.time()

    def update(self) -> None:
        now = time.time()
        elapsed = now - self.last_leak
        self.last_leak = now
        self.current_fill = max(0.0, self.current_fill - elapsed * self.leak_rate)

    def admit(self, packet_bytes: int) -> bool:
        self.update()
        if self.current_fill + packet_bytes <= self.capacity:
            self.current_fill += packet_bytes
            return True
        return False


class PriorityQueue:
    """
    Multi-level Strict Priority Scheduler (e.g. Voice > Video > Best-Effort).
    """
    def __init__(self, levels: int = 4):
        self.queues: List[Deque[bytes]] = [deque() for _ in range(levels)]

    def enqueue(self, priority: int, packet: bytes) -> None:
        p = max(0, min(priority, len(self.queues) - 1))
        self.queues[p].append(packet)

    def dequeue(self) -> Optional[bytes]:
        # Highest priority (index 0) first
        for q in self.queues:
            if q:
                return q.popleft()
        return None


class WeightedFairQueue:
    """
    Weighted Fair Queuing (WFQ) Scheduler:
    Shares bandwidth proportionally according to assigned flow weights.
    """
    def __init__(self, flow_weights: List[float]):
        self.weights = flow_weights
        self.queues: List[Deque[bytes]] = [deque() for _ in flow_weights]
        self.virtual_times: List[float] = [0.0 for _ in flow_weights]

    def enqueue(self, flow_id: int, packet: bytes) -> None:
        if 0 <= flow_id < len(self.queues):
            self.queues[flow_id].append(packet)

    def dequeue(self) -> Optional[Tuple[int, bytes]]:
        # Pick flow with smallest virtual finish time
        best_flow = -1
        min_vtime = float("inf")
        for i, q in enumerate(self.queues):
            if q:
                if self.virtual_times[i] < min_vtime:
                    min_vtime = self.virtual_times[i]
                    best_flow = i

        if best_flow == -1:
            return None

        pkt = self.queues[best_flow].popleft()
        # Advance virtual time by packet length / weight
        self.virtual_times[best_flow] += len(pkt) / max(0.01, self.weights[best_flow])
        return best_flow, pkt


class RandomEarlyDetection:
    """
    Random Early Detection (RED - RFC 2309):
    Avoids global synchronization in TCP congestion by dropping packets probabilistically
    before queue becomes full.
    """
    def __init__(self, min_th: int = 5, max_th: int = 15, max_p: float = 0.1, weight: float = 0.002):
        self.min_th = min_th
        self.max_th = max_th
        self.max_p = max_p
        self.weight = weight
        self.avg_queue_len: float = 0.0
        self.current_queue_len: int = 0

    def should_drop(self, current_queue_size: int) -> bool:
        self.current_queue_len = current_queue_size
        # EWMA average queue length
        self.avg_queue_len = (1.0 - self.weight) * self.avg_queue_len + self.weight * current_queue_size

        if self.avg_queue_len < self.min_th:
            return False
        elif self.avg_queue_len >= self.max_th:
            return True
        else:
            # Linear probability between min_th and max_th
            pb = self.max_p * (self.avg_queue_len - self.min_th) / (self.max_th - self.min_th)
            return random.random() < pb
