"""
TCP Congestion Control Simulation Models:
- TCP Tahoe (Slow Start + Congestion Avoidance + Fast Retransmit)
- TCP Reno (Fast Recovery)
- TCP CUBIC (RFC 8312 - Default Linux Congestion Algorithm)
- TCP BBR (Bottleneck Bandwidth and RTT Model)
"""
from __future__ import annotations
import math
import time
from dataclasses import dataclass
from typing import List, Tuple


class TCPTahoeModel:
    """
    TCP Tahoe:
    - Loss -> cwnd = 1, ssthresh = cwnd / 2
    """
    def __init__(self, initial_cwnd: float = 1.0, initial_ssthresh: float = 64.0):
        self.cwnd = initial_cwnd
        self.ssthresh = initial_ssthresh

    def on_ack(self) -> None:
        if self.cwnd < self.ssthresh:
            # Slow Start: cwnd += 1 per ACK (exponential)
            self.cwnd += 1.0
        else:
            # Congestion Avoidance: cwnd += 1 / cwnd per ACK (linear)
            self.cwnd += 1.0 / self.cwnd

    def on_loss(self) -> None:
        self.ssthresh = max(2.0, self.cwnd / 2.0)
        self.cwnd = 1.0


class TCPRenoModel:
    """
    TCP Reno:
    - Loss via 3 dup ACKs -> Fast Recovery: ssthresh = cwnd / 2, cwnd = ssthresh + 3
    - Loss via RTO -> cwnd = 1, ssthresh = cwnd / 2
    """
    def __init__(self, initial_cwnd: float = 1.0, initial_ssthresh: float = 64.0):
        self.cwnd = initial_cwnd
        self.ssthresh = initial_ssthresh
        self.in_fast_recovery = False

    def on_ack(self) -> None:
        if self.in_fast_recovery:
            self.cwnd = self.ssthresh
            self.in_fast_recovery = False

        if self.cwnd < self.ssthresh:
            self.cwnd += 1.0
        else:
            self.cwnd += 1.0 / self.cwnd

    def on_duplicate_ack(self, dup_count: int) -> None:
        if dup_count == 3:
            self.ssthresh = max(2.0, self.cwnd / 2.0)
            self.cwnd = self.ssthresh + 3.0
            self.in_fast_recovery = True
        elif dup_count > 3 and self.in_fast_recovery:
            self.cwnd += 1.0

    def on_timeout(self) -> None:
        self.ssthresh = max(2.0, self.cwnd / 2.0)
        self.cwnd = 1.0
        self.in_fast_recovery = False


class TCPCubicModel:
    """
    TCP CUBIC (RFC 8312):
    Window growth is governed by a cubic function of elapsed time 't' since the last congestion event:
    W_cubic(t) = C * (t - K)^3 + W_max
    where K = (W_max * beta / C)^(1/3)
    """
    def __init__(self, initial_cwnd: float = 10.0):
        self.cwnd = initial_cwnd
        self.w_max = initial_cwnd
        self.epoch_start: float = time.time()
        self.C = 0.4        # Cubic scaling constant
        self.beta = 0.7     # Multiplicative decrease factor (0.7 in CUBIC vs 0.5 in Reno)
        self.k = 0.0

    def on_loss(self) -> None:
        self.w_max = self.cwnd
        self.cwnd = max(2.0, self.cwnd * self.beta)
        self.epoch_start = time.time()
        # K = cuberoot((W_max - cwnd) / C)
        diff = max(0.0, (self.w_max - self.cwnd) / self.C)
        self.k = math.pow(diff, 1.0 / 3.0)

    def on_ack(self) -> None:
        t = time.time() - self.epoch_start
        target_w = self.C * math.pow(t - self.k, 3) + self.w_max
        if target_w > self.cwnd:
            self.cwnd += (target_w - self.cwnd) / self.cwnd
        else:
            self.cwnd += 1.0 / self.cwnd


class TCPBBRModel:
    """
    TCP BBR (Bottleneck Bandwidth and RTT):
    State machine: STARTUP, DRAIN, PROBE_BW, PROBE_RTT.
    Maintains min_rtt and max_bandwidth estimates.
    """
    def __init__(self):
        self.state = "STARTUP"
        self.pacing_gain = 2.885
        self.cwnd_gain = 2.885
        self.min_rtt = float("inf")
        self.max_bw = 0.0  # bps
        self.cwnd = 10.0

    def update_estimates(self, delivery_rate_bps: float, rtt_sec: float) -> None:
        self.max_bw = max(self.max_bw, delivery_rate_bps)
        self.min_rtt = min(self.min_rtt, rtt_sec)

        # BDP = max_bw * min_rtt
        bdp_packets = (self.max_bw * self.min_rtt) / (1500.0 * 8.0)
        self.cwnd = max(4.0, bdp_packets * self.cwnd_gain)
