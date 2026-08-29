"""
Network checksum calculation algorithms: Internet Checksum (RFC 1071), CRC16, CRC32, Adler32, Fletcher16.
"""
from __future__ import annotations
import struct
from typing import Union


def calculate_internet_checksum(data: Union[bytes, bytearray]) -> int:
    """
    Compute 16-bit One's Complement Internet Checksum (RFC 1071).
    Used in IPv4, ICMP, IGMP, TCP, and UDP headers.
    """
    length = len(data)
    total_sum = 0

    # Process 16-bit words (2 bytes at a time)
    for i in range(0, length - 1, 2):
        word = (data[i] << 8) + data[i + 1]
        total_sum += word

    # If odd length, pad with 0 byte
    if length % 2 != 0:
        total_sum += data[-1] << 8

    # Fold 32-bit sum into 16 bits
    while (total_sum >> 16) > 0:
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)

    # One's complement invert
    checksum = ~total_sum & 0xFFFF
    return checksum


def update_internet_checksum(old_csum: int, old_word: int, new_word: int) -> int:
    """
    Incremental 16-bit checksum update (RFC 1624 Eqn 3).
    Allows fast recalculation when a field (like TTL or NAT IP) is changed.
    """
    # ~C' = ~C + ~m + m' = ~C + (m' - m)
    hc = ~old_csum & 0xFFFF
    hc = hc - old_word + new_word
    while (hc >> 16) > 0 or hc < 0:
        if hc < 0:
            hc = (hc & 0xFFFF) - 1
        else:
            hc = (hc & 0xFFFF) + (hc >> 16)
    return ~hc & 0xFFFF


def calculate_crc16(data: Union[bytes, bytearray], polynomial: int = 0x1021, init_val: int = 0xFFFF) -> int:
    """
    CRC-16-CCITT implementation.
    """
    crc = init_val
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ polynomial) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def calculate_crc32(data: Union[bytes, bytearray]) -> int:
    """
    Standard IEEE 802.3 CRC-32 calculation for Ethernet FCS.
    Polynomial: 0xEDB88320 (reversed 0x04C11DB7).
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            mask = -(crc & 1)
            crc = (crc >> 1) ^ (0xEDB88320 & mask)
    return ~crc & 0xFFFFFFFF


def calculate_adler32(data: Union[bytes, bytearray]) -> int:
    """
    Adler-32 checksum (RFC 1950).
    """
    MOD_ADLER = 65521
    a = 1
    b = 0
    for byte in data:
        a = (a + byte) % MOD_ADLER
        b = (b + a) % MOD_ADLER
    return (b << 16) | a


def calculate_fletcher16(data: Union[bytes, bytearray]) -> int:
    """
    Fletcher-16 checksum algorithm.
    """
    c0 = 0
    c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0


def compute_pseudo_header_checksum(
    src_ip_bytes: bytes,
    dst_ip_bytes: bytes,
    protocol: int,
    payload_length: int,
    payload_bytes: bytes,
) -> int:
    """
    Compute TCP/UDP Checksum including IPv4 Pseudo-Header (RFC 793 / RFC 768).
    Pseudo-header structure:
    - 4 bytes Source IP
    - 4 bytes Destination IP
    - 1 byte Zero padding
    - 1 byte Protocol Number
    - 2 bytes TCP/UDP Segment Length
    - Followed by the TCP/UDP Header + Payload
    """
    pseudo_hdr = bytearray()
    pseudo_hdr.extend(src_ip_bytes)
    pseudo_hdr.extend(dst_ip_bytes)
    pseudo_hdr.append(0)
    pseudo_hdr.append(protocol & 0xFF)
    pseudo_hdr.extend(struct.pack("!H", payload_length))

    full_segment = pseudo_hdr + payload_bytes
    return calculate_internet_checksum(full_segment)
