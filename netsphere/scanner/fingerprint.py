"""
TCP/IP Stack OS Fingerprinting Engine:
Deduces target operating system by analyzing SYN-ACK response attributes:
- Initial TTL (Linux/FreeBSD ~64, Windows ~128, Cisco IOS ~255)
- Initial Window Size
- DF (Don't Fragment) Bit
- TCP Options and Order
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Dict


@dataclass
class OSFingerprintResult:
    os_name: str
    confidence: float
    ttl: int
    window_size: int
    df_bit: bool
    details: str


class OSFingerprinter:
    """
    OS Heuristics based on TCP/IP stack implementation signatures.
    """
    SIGNATURES = [
        {"os": "Linux (Kernel 3.x - 6.x)", "ttl_min": 50, "ttl_max": 64, "win": [5840, 14600, 29200, 64240], "df": True},
        {"os": "Microsoft Windows (10/11/Server 2016-2022)", "ttl_min": 100, "ttl_max": 128, "win": [8192, 64240, 65535], "df": True},
        {"os": "Apple macOS / iOS", "ttl_min": 50, "ttl_max": 64, "win": [65535], "df": True},
        {"os": "FreeBSD / OpenBSD", "ttl_min": 50, "ttl_max": 64, "win": [16384, 65535], "df": True},
        {"os": "Cisco IOS / Network Device", "ttl_min": 200, "ttl_max": 255, "win": [4128, 8192], "df": False},
        {"os": "Solaris / SunOS", "ttl_min": 200, "ttl_max": 255, "win": [24616, 32768], "df": False},
    ]

    def analyze(self, ttl: int, window_size: int, df_bit: bool = True) -> OSFingerprintResult:
        best_match = "Unknown OS"
        best_score = 0.0
        details = ""

        for sig in self.SIGNATURES:
            score = 0.0
            # Check TTL
            if sig["ttl_min"] <= ttl <= sig["ttl_max"]:
                score += 0.5
            elif abs(ttl - sig["ttl_max"]) <= 10:
                score += 0.3

            # Check Window Size
            if window_size in sig["win"]:
                score += 0.3
            elif window_size % 1024 == 0:
                score += 0.1

            # Check DF bit
            if df_bit == sig["df"]:
                score += 0.2

            if score > best_score:
                best_score = score
                best_match = sig["os"]
                details = f"TTL={ttl} (Range {sig['ttl_min']}-{sig['ttl_max']}), Window={window_size}, DF={df_bit}"

        confidence = min(1.0, best_score)
        return OSFingerprintResult(
            os_name=best_match,
            confidence=confidence,
            ttl=ttl,
            window_size=window_size,
            df_bit=df_bit,
            details=details,
        )
