"""
Core primitives, buffer management, byte manipulation, checksums, and event bus.
"""

from netsphere.core.types import (
    IPv4Address,
    IPv6Address,
    MACAddress,
    Port,
    ProtocolNumber,
    SubnetMask,
    CIDRNetwork,
    InterfaceState,
    LinkType,
    PacketDirection,
    EtherType,
    TransportProtocol,
)
from netsphere.core.buffer import PacketBuffer
from netsphere.core.bitfield import BitField, BitMask, extract_bits, pack_bits
from netsphere.core.checksum import (
    calculate_internet_checksum,
    calculate_crc16,
    calculate_crc32,
    calculate_adler32,
    calculate_fletcher16,
    compute_pseudo_header_checksum,
)
from netsphere.core.events import (
    EventBus,
    Event,
    PacketReceivedEvent,
    PacketDroppedEvent,
    InterfaceStateChangeEvent,
    RouteAddedEvent,
    AnomalyAlertEvent,
)

__all__ = [
    "IPv4Address",
    "IPv6Address",
    "MACAddress",
    "Port",
    "ProtocolNumber",
    "SubnetMask",
    "CIDRNetwork",
    "InterfaceState",
    "LinkType",
    "PacketDirection",
    "EtherType",
    "TransportProtocol",
    "PacketBuffer",
    "BitField",
    "BitMask",
    "extract_bits",
    "pack_bits",
    "calculate_internet_checksum",
    "calculate_crc16",
    "calculate_crc32",
    "calculate_adler32",
    "calculate_fletcher16",
    "compute_pseudo_header_checksum",
    "EventBus",
    "Event",
    "PacketReceivedEvent",
    "PacketDroppedEvent",
    "InterfaceStateChangeEvent",
    "RouteAddedEvent",
    "AnomalyAlertEvent",
]
