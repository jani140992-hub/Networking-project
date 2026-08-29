"""
sFlow Version 5 Packet Sampling Architecture (RFC 3176).
"""
from __future__ import annotations
import time
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SFlowSample:
    sequence: int
    source_id: int
    sampling_rate: int
    sample_pool: int
    drops: int
    input_interface: int
    output_interface: int
    packet_data: bytes


class SFlowCollector:
    """Collector for sampled sFlow packets."""
    def __init__(self):
        self.samples: List[SFlowSample] = []

    def record_sample(self, sample: SFlowSample):
        self.samples.append(sample)
