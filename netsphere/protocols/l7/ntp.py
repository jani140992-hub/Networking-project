"""
Network Time Protocol Version 4 (NTPv4 - RFC 5905).
"""
from __future__ import annotations
import time
from netsphere.core.buffer import PacketBuffer
from netsphere.protocols.base import DissectionError


class NTPMessage:
    """
    NTP Packet Header (48 bytes):
    - Leap Indicator (2 bits) + Version (3 bits) + Mode (3 bits)
    - Stratum (1 byte)
    - Poll (1 byte)
    - Precision (1 byte signed)
    - Root Delay (4 bytes fixed point)
    - Root Dispersion (4 bytes fixed point)
    - Reference ID (4 bytes)
    - Reference Timestamp (8 bytes)
    - Origin Timestamp (8 bytes)
    - Receive Timestamp (8 bytes)
    - Transmit Timestamp (8 bytes)
    """
    NTP_DELTA = 2208988800  # Seconds between 1 Jan 1900 and 1 Jan 1970

    def __init__(
        self,
        leap_indicator: int = 0,
        version: int = 4,
        mode: int = 3, # 3=Client, 4=Server
        stratum: int = 2,
        poll: int = 4,
        precision: int = -6,
    ):
        self.leap_indicator = leap_indicator
        self.version = version
        self.mode = mode
        self.stratum = stratum
        self.poll = poll
        self.precision = precision
        self.transmit_timestamp: float = time.time()

    def pack(self) -> bytes:
        b1 = ((self.leap_indicator & 0x03) << 6) | ((self.version & 0x07) << 3) | (self.mode & 0x07)
        buf = PacketBuffer()
        buf.write_uint8(b1)
        buf.write_uint8(self.stratum)
        buf.write_uint8(self.poll)
        buf.write_int8(self.precision)
        buf.write_uint32_be(0) # Root delay
        buf.write_uint32_be(0) # Root dispersion
        buf.write_bytes(b"LOCL")
        buf.write_bytes(b"\x00" * 24) # Ref, Orig, Recv timestamps

        # Transmit timestamp (64-bit NTP timestamp)
        secs = int(self.transmit_timestamp + self.NTP_DELTA)
        frac = int((self.transmit_timestamp % 1.0) * (2**32))
        buf.write_uint32_be(secs)
        buf.write_uint32_be(frac)
        return buf.to_bytes()

    @classmethod
    def unpack(cls, buffer: PacketBuffer) -> NTPMessage:
        if buffer.remaining < 48:
            raise DissectionError("Buffer underflow unpacking NTP packet")
        b1 = buffer.read_uint8()
        li = (b1 >> 6) & 0x03
        ver = (b1 >> 3) & 0x07
        mode = b1 & 0x07
        strat = buffer.read_uint8()
        poll = buffer.read_uint8()
        prec = buffer.read_int8()
        buffer.read_bytes(36)
        secs = buffer.read_uint32_be()
        frac = buffer.read_uint32_be()
        ts = (secs - cls.NTP_DELTA) + (frac / (2**32))

        msg = cls(leap_indicator=li, version=ver, mode=mode, stratum=strat, poll=poll, precision=prec)
        msg.transmit_timestamp = ts
        return msg
