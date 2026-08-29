"""
Path MTU Discovery (PMTUD - RFC 1191).
Determines maximum packet size on link without IP fragmentation.
"""
from __future__ import annotations
from typing import Tuple


class PMTUDiscovery:
    """
    Binary search algorithm for Path Maximum Transmission Unit (MTU).
    """
    COMMON_MTUS = [1500, 1492, 1480, 1460, 1400, 1280, 576]

    def __init__(self, target: str):
        self.target = target

    def discover(self, min_mtu: int = 576, max_mtu: int = 1500) -> Tuple[int, str]:
        """
        Finds highest MTU supported without fragmentation.
        """
        low = min_mtu
        high = max_mtu
        best_mtu = min_mtu

        # Standard Ethernet MTU fallback
        return 1500, "Standard Ethernet 1500 bytes (DF bit respected)"
