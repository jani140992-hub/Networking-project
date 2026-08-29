"""
NetSphere Core Package Generator.
Generates netsphere/core/* and root __init__.py.
"""
from common import write_code_file

def generate_core():
    total_lines = 0
    print("[*] Generating NetSphere Core modules...")

    # netsphere/__init__.py
    content_init = '''"""
NetSphere: Enterprise Network Operations, Protocol Engineering & Telemetry Platform.

A comprehensive modular Python networking suite providing:
- L2-L7 protocol dissection, serialization, and state machines
- SDN topology simulation, virtual switching, and LPM routing
- Traffic shaping (Token Bucket, RED, WFQ) and TCP congestion control
- Multi-vector port scanning and OS fingerprinting
- High-precision diagnostics (Ping, Traceroute, PMTU, Bandwidth)
- NetFlow/sFlow telemetry collection and real-time anomaly detection
- Embedded REST and WebSocket operations server
- Enterprise network catalogs (IANA ports, protocols, MIBs, OUI)
"""

__version__ = "1.0.0"
__author__ = "NetSphere Engineering Team"
__license__ = "Proprietary"

from netsphere.core.types import IPv4Address, IPv6Address, MACAddress, Port, CIDRNetwork
from netsphere.core.buffer import PacketBuffer
from netsphere.core.events import EventBus

__all__ = [
    "__version__",
    "IPv4Address",
    "IPv6Address",
    "MACAddress",
    "Port",
    "CIDRNetwork",
    "PacketBuffer",
    "EventBus",
]
'''
    total_lines += write_code_file("netsphere/__init__.py", content_init)

    # netsphere/core/__init__.py
    content_core_init = '''"""
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
'''
    total_lines += write_code_file("netsphere/core/__init__.py", content_core_init)

    # netsphere/core/types.py
    content_types = '''"""
Networking data types, address abstractions, and protocol enumerations.
"""
from __future__ import annotations
import enum
import struct
from dataclasses import dataclass
from typing import Union, Optional, Tuple, List


class EtherType(enum.IntEnum):
    """Common IEEE 802.3 / Ethernet II EtherTypes."""
    IPV4 = 0x0800
    ARP = 0x0806
    WOL = 0x0842
    RARP = 0x8035
    VLAN_8021Q = 0x8100
    IPV6 = 0x86DD
    MPLS_UNICAST = 0x8847
    MPLS_MULTICAST = 0x8848
    PPPOE_DISCOVERY = 0x8863
    PPPOE_SESSION = 0x8864
    LLDP = 0x88CC
    IEEE_8021AD_QINQ = 0x88A8
    EAPOL = 0x888E
    MAC_SECURITY = 0x88E5
    PTP_1588 = 0x88F7


class TransportProtocol(enum.IntEnum):
    """Standard IP Transport Protocol Numbers (RFC 790 / IANA)."""
    HOPOPT = 0
    ICMP = 1
    IGMP = 2
    GGP = 3
    IPV4_ENCAP = 4
    ST = 5
    TCP = 6
    CBT = 7
    EGP = 8
    IGP = 9
    BBN_RCC_MON = 10
    NVP_II = 11
    PUP = 12
    ARGUS = 13
    EMCON = 14
    XNET = 15
    CHAOS = 16
    UDP = 17
    TMux = 18
    DCN_MEAS = 19
    HMP = 20
    PRM = 21
    XNS_IDP = 22
    TRUNK_1 = 23
    TRUNK_2 = 24
    LEAF_1 = 25
    LEAF_2 = 26
    RDP = 27
    IRTP = 28
    ISO_TP4 = 29
    NETBLT = 30
    MFE_NSP = 31
    MERIT_INP = 32
    DCCP = 33
    THIRD_PC = 34
    IDPR = 35
    XTP = 36
    DDP = 37
    IDPR_CMTP = 38
    TP_PLUS_PLUS = 39
    IL = 40
    IPV6 = 41
    SDRP = 42
    IPV6_ROUTE = 43
    IPV6_FRAG = 44
    IDRP = 45
    RSVP = 46
    GRE = 47
    DSR = 48
    BNA = 49
    ESP = 50
    AH = 51
    I_NLSP = 52
    SWIPE = 53
    NARP = 54
    MOBILE = 55
    TLSP = 56
    SKIP = 57
    IPV6_ICMP = 58
    IPV6_NONXT = 59
    IPV6_OPTS = 60
    CFTP = 62
    SAT_EXPAK = 64
    KRYPTOLAN = 65
    RVD = 66
    IPPC = 67
    SAT_MON = 69
    VISA = 70
    IPCV = 71
    CPNX = 72
    CPHB = 73
    WSN = 74
    PVP = 75
    BR_SAT_MON = 76
    SUN_ND = 77
    WB_MON = 78
    WB_EXPAK = 79
    ISO_IP = 80
    VMTP = 81
    SECURE_VMTP = 82
    VINES = 83
    TTP = 84
    IPTM = 84
    NSFNET_IGP = 85
    DGP = 86
    TCF = 87
    EIGRP = 88
    OSPFIGP = 89
    Sprite_RPC = 90
    LARP = 91
    MTP = 92
    AX25 = 93
    IPIP = 94
    MICP = 95
    SCC_SP = 96
    ETHERIP = 97
    ENCAP = 98
    GMTP = 100
    IFMP = 101
    PNNI = 102
    PIM = 103
    ARIS = 104
    SCPS = 105
    QNX = 106
    A_N = 107
    IPComp = 108
    SNP = 109
    Compaq_Peer = 110
    IPX_in_IP = 111
    VRRP = 112
    PGM = 113
    L2TP = 115
    DDX = 116
    IATP = 117
    STP = 118
    SRP = 119
    UTI = 120
    SMP = 121
    SM = 122
    PTP = 123
    ISIS_over_IPv4 = 124
    FIRE = 125
    CRTP = 126
    CRUDP = 127
    SSCOPMCE = 128
    IPLT = 129
    SPS = 130
    PIPE = 131
    SCTP = 132
    FC = 133
    RSVP_E2E_IGNORE = 134
    Mobility_Header = 135
    UDPLite = 136
    MPLS_in_IP = 137
    manet = 138
    HIP = 139
    Shim6 = 140
    WESP = 141
    ROHC = 142
    Ethernet = 143
    AGGFRAG = 144
    NSH = 145


class InterfaceState(enum.Enum):
    """Network Interface operational status."""
    UP = "up"
    DOWN = "down"
    TESTING = "testing"
    UNKNOWN = "unknown"
    DORMANT = "dormant"
    NOT_PRESENT = "not_present"
    LOWER_LAYER_DOWN = "lower_layer_down"


class LinkType(enum.Enum):
    """Physical and virtual link types."""
    ETHERNET = "ethernet"
    FIBER = "fiber"
    WIRELESS_80211 = "802.11"
    POINT_TO_POINT = "p2p"
    LOOPBACK = "loopback"
    VLAN = "vlan"
    TUNNEL_GRE = "gre_tunnel"
    TUNNEL_VXLAN = "vxlan"


class PacketDirection(enum.Enum):
    """Direction of packet flow relative to a node/interface."""
    INGRESS = "ingress"
    EGRESS = "egress"
    INTERNAL = "internal"


@dataclass(frozen=True)
class MACAddress:
    """Represents a 48-bit IEEE 802 MAC address."""
    raw_bytes: bytes

    def __init__(self, value: Union[bytes, str]):
        if isinstance(value, bytes):
            if len(value) != 6:
                raise ValueError(f"MAC address byte length must be 6, got {len(value)}")
            object.__setattr__(self, "raw_bytes", value)
        elif isinstance(value, str):
            clean_str = value.replace(":", "").replace("-", "").replace(".", "")
            if len(clean_str) != 12:
                raise ValueError(f"Invalid MAC address string format: {value}")
            raw = bytes.fromhex(clean_str)
            object.__setattr__(self, "raw_bytes", raw)
        else:
            raise TypeError(f"Cannot initialize MACAddress from {type(value)}")

    def __str__(self) -> str:
        return ":".join(f"{b:02x}" for b in self.raw_bytes)

    def __repr__(self) -> str:
        return f"MACAddress('{str(self)}')"

    @property
    def is_multicast(self) -> bool:
        """Check if MAC is an IEEE 802 multicast address (bit 0 of first octet is 1)."""
        return bool(self.raw_bytes[0] & 0x01)

    @property
    def is_broadcast(self) -> bool:
        """Check if MAC is the broadcast address (ff:ff:ff:ff:ff:ff)."""
        return self.raw_bytes == b"\\xff\\xff\\xff\\xff\\xff\\xff"

    @property
    def is_unicast(self) -> bool:
        return not self.is_multicast and not self.is_broadcast

    @property
    def is_locally_administered(self) -> bool:
        """Check if MAC is locally administered (bit 1 of first octet is 1)."""
        return bool(self.raw_bytes[0] & 0x02)

    @property
    def oui(self) -> str:
        """Return the 24-bit Organizationally Unique Identifier as hex string."""
        return ":".join(f"{b:02X}" for b in self.raw_bytes[:3])

    @classmethod
    def broadcast(cls) -> MACAddress:
        return cls(b"\\xff\\xff\\xff\\xff\\xff\\xff")

    @classmethod
    def zero(cls) -> MACAddress:
        return cls(b"\\x00\\x00\\x00\\x00\\x00\\x00")


@dataclass(frozen=True)
class IPv4Address:
    """Represents a 32-bit IPv4 address."""
    packed: bytes

    def __init__(self, value: Union[bytes, str, int]):
        if isinstance(value, bytes):
            if len(value) != 4:
                raise ValueError(f"IPv4 packed bytes must be 4, got {len(value)}")
            object.__setattr__(self, "packed", value)
        elif isinstance(value, int):
            if not 0 <= value <= 0xFFFFFFFF:
                raise ValueError(f"IPv4 integer out of range: {value}")
            object.__setattr__(self, "packed", struct.pack("!I", value))
        elif isinstance(value, str):
            parts = value.strip().split(".")
            if len(parts) != 4:
                raise ValueError(f"Invalid IPv4 string representation: {value}")
            octets = []
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    raise ValueError(f"IPv4 octet out of range: {num} in {value}")
                octets.append(num)
            object.__setattr__(self, "packed", bytes(octets))
        else:
            raise TypeError(f"Cannot initialize IPv4Address from {type(value)}")

    def __str__(self) -> str:
        return ".".join(str(b) for b in self.packed)

    def __repr__(self) -> str:
        return f"IPv4Address('{str(self)}')"

    def to_int(self) -> int:
        return struct.unpack("!I", self.packed)[0]

    @property
    def is_loopback(self) -> bool:
        """Check if 127.0.0.0/8 loopback."""
        return self.packed[0] == 127

    @property
    def is_private(self) -> bool:
        """Check RFC 1918 private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."""
        b0, b1 = self.packed[0], self.packed[1]
        if b0 == 10:
            return True
        if b0 == 172 and (16 <= b1 <= 31):
            return True
        if b0 == 192 and b1 == 168:
            return True
        return False

    @property
    def is_multicast(self) -> bool:
        """Check Class D multicast 224.0.0.0/4."""
        return (self.packed[0] & 0xF0) == 0xE0

    @property
    def is_link_local(self) -> bool:
        """Check RFC 3927 link-local 169.254.0.0/16."""
        return self.packed[0] == 169 and self.packed[1] == 254

    @property
    def is_broadcast(self) -> bool:
        return self.packed == b"\\xff\\xff\\xff\\xff"

    @classmethod
    def loopback(cls) -> IPv4Address:
        return cls("127.0.0.1")

    @classmethod
    def any_addr(cls) -> IPv4Address:
        return cls("0.0.0.0")

    @classmethod
    def broadcast_addr(cls) -> IPv4Address:
        return cls("255.255.255.255")


@dataclass(frozen=True)
class IPv6Address:
    """Represents a 128-bit IPv6 address."""
    packed: bytes

    def __init__(self, value: Union[bytes, str, int]):
        if isinstance(value, bytes):
            if len(value) != 16:
                raise ValueError(f"IPv6 packed bytes must be 16, got {len(value)}")
            object.__setattr__(self, "packed", value)
        elif isinstance(value, int):
            if not 0 <= value <= (2**128 - 1):
                raise ValueError(f"IPv6 integer out of range: {value}")
            object.__setattr__(self, "packed", value.to_bytes(16, byteorder="big"))
        elif isinstance(value, str):
            # Parse IPv6 string with optional :: compression
            clean_str = value.strip().lower()
            if "::" in clean_str:
                left_str, right_str = clean_str.split("::", 1)
                left_parts = [p for p in left_str.split(":") if p]
                right_parts = [p for p in right_str.split(":") if p]
                fill_count = 8 - (len(left_parts) + len(right_parts))
                if fill_count < 1:
                    raise ValueError(f"Invalid IPv6 compression: {value}")
                parts = left_parts + ["0"] * fill_count + right_parts
            else:
                parts = clean_str.split(":")
            if len(parts) != 8:
                raise ValueError(f"Invalid IPv6 representation: {value}")
            hextets = [int(p, 16) for p in parts]
            packed = struct.pack("!8H", *hextets)
            object.__setattr__(self, "packed", packed)
        else:
            raise TypeError(f"Cannot initialize IPv6Address from {type(value)}")

    def __str__(self) -> str:
        hextets = struct.unpack("!8H", self.packed)
        return ":".join(f"{h:x}" for h in hextets)

    def __repr__(self) -> str:
        return f"IPv6Address('{str(self)}')"

    def to_int(self) -> int:
        return int.from_bytes(self.packed, byteorder="big")

    @property
    def is_loopback(self) -> bool:
        return self.packed == (b"\\x00" * 15 + b"\\x01")

    @property
    def is_unspecified(self) -> bool:
        return self.packed == (b"\\x00" * 16)

    @property
    def is_multicast(self) -> bool:
        return self.packed[0] == 0xFF

    @property
    def is_link_local(self) -> bool:
        return (self.packed[0] == 0xFE) and ((self.packed[1] & 0xC0) == 0x80)

    @classmethod
    def loopback(cls) -> IPv6Address:
        return cls("::1")


@dataclass(frozen=True)
class SubnetMask:
    """Represents an IPv4 subnet mask."""
    prefix_len: int

    def __init__(self, value: Union[int, str, IPv4Address]):
        if isinstance(value, int):
            if not 0 <= value <= 32:
                raise ValueError(f"Subnet prefix length must be 0-32, got {value}")
            object.__setattr__(self, "prefix_len", value)
        elif isinstance(value, (str, IPv4Address)):
            addr = IPv4Address(value) if isinstance(value, str) else value
            mask_int = addr.to_int()
            # Count leading 1s
            bin_str = bin(mask_int)[2:].zfill(32)
            if "01" in bin_str:
                raise ValueError(f"Non-contiguous subnet mask: {value}")
            object.__setattr__(self, "prefix_len", bin_str.count("1"))
        else:
            raise TypeError(f"Invalid subnet mask initializer: {type(value)}")

    def to_ipv4(self) -> IPv4Address:
        if self.prefix_len == 0:
            return IPv4Address(0)
        mask_int = ((1 << self.prefix_len) - 1) << (32 - self.prefix_len)
        return IPv4Address(mask_int)

    def __str__(self) -> str:
        return str(self.to_ipv4())

    def __repr__(self) -> str:
        return f"SubnetMask(/{self.prefix_len})"


@dataclass(frozen=True)
class CIDRNetwork:
    """Represents an IPv4 CIDR Network block."""
    network_address: IPv4Address
    prefix_len: int

    def __init__(self, cidr_str: str):
        if "/" not in cidr_str:
            raise ValueError(f"CIDR string must contain '/', got '{cidr_str}'")
        addr_str, prefix_str = cidr_str.strip().split("/", 1)
        prefix = int(prefix_str)
        if not 0 <= prefix <= 32:
            raise ValueError(f"Prefix length must be 0-32, got {prefix}")
        mask_int = ((1 << prefix) - 1) << (32 - prefix) if prefix > 0 else 0
        raw_addr = IPv4Address(addr_str).to_int()
        net_int = raw_addr & mask_int
        object.__setattr__(self, "network_address", IPv4Address(net_int))
        object.__setattr__(self, "prefix_len", prefix)

    @property
    def netmask(self) -> SubnetMask:
        return SubnetMask(self.prefix_len)

    @property
    def broadcast_address(self) -> IPv4Address:
        if self.prefix_len == 32:
            return self.network_address
        host_mask = (1 << (32 - self.prefix_len)) - 1
        bcast_int = self.network_address.to_int() | host_mask
        return IPv4Address(bcast_int)

    @property
    def num_addresses(self) -> int:
        return 1 << (32 - self.prefix_len)

    @property
    def num_usable_hosts(self) -> int:
        if self.prefix_len >= 31:
            return 0
        return self.num_addresses - 2

    def contains(self, addr: Union[IPv4Address, str]) -> bool:
        if isinstance(addr, str):
            addr = IPv4Address(addr)
        mask_int = ((1 << self.prefix_len) - 1) << (32 - self.prefix_len) if self.prefix_len > 0 else 0
        return (addr.to_int() & mask_int) == self.network_address.to_int()

    def __contains__(self, addr: Union[IPv4Address, str]) -> bool:
        return self.contains(addr)

    def __str__(self) -> str:
        return f"{self.network_address}/{self.prefix_len}"

    def __repr__(self) -> str:
        return f"CIDRNetwork('{str(self)}')"


@dataclass(frozen=True)
class Port:
    """Represents a 16-bit TCP/UDP Transport Layer Port."""
    value: int

    def __init__(self, value: int):
        if not 0 <= value <= 65535:
            raise ValueError(f"Port number must be 0-65535, got {value}")
        object.__setattr__(self, "value", value)

    @property
    def is_well_known(self) -> bool:
        """System / Well-known ports: 0 - 1023."""
        return 0 <= self.value <= 1023

    @property
    def is_registered(self) -> bool:
        """User / Registered ports: 1024 - 49151."""
        return 1024 <= self.value <= 49151

    @property
    def is_dynamic(self) -> bool:
        """Dynamic / Private / Ephemeral ports: 49152 - 65535."""
        return 49152 <= self.value <= 65535

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return f"Port({self.value})"

    def __int__(self) -> int:
        return self.value


@dataclass(frozen=True)
class ProtocolNumber:
    """Represents an 8-bit IP Protocol Number."""
    value: int

    def __init__(self, value: int):
        if not 0 <= value <= 255:
            raise ValueError(f"IP Protocol number must be 0-255, got {value}")
        object.__setattr__(self, "value", value)

    def __str__(self) -> str:
        return str(self.value)

    def __int__(self) -> int:
        return self.value
'''
    total_lines += write_code_file("netsphere/core/types.py", content_types)

    # netsphere/core/buffer.py
    content_buffer = '''"""
PacketBuffer: high-performance byte manipulation, cursor management, and bit packing.
"""
from __future__ import annotations
import struct
from typing import Union, List, Optional


class PacketBuffer:
    """
    Mutable/Immutable network packet byte buffer.
    Provides cursor-based reading and writing of standard protocol primitives.
    """
    def __init__(self, data: Optional[Union[bytes, bytearray, List[int]]] = None):
        if data is None:
            self._buffer = bytearray()
        elif isinstance(data, bytearray):
            self._buffer = data
        elif isinstance(data, bytes):
            self._buffer = bytearray(data)
        elif isinstance(data, list):
            self._buffer = bytearray(data)
        else:
            raise TypeError(f"Invalid data type for PacketBuffer: {type(data)}")
        self._cursor: int = 0

    @classmethod
    def from_hex(cls, hex_str: str) -> PacketBuffer:
        clean = "".join(hex_str.split())
        return cls(bytes.fromhex(clean))

    def to_hex(self, separator: str = " ") -> str:
        return separator.join(f"{b:02x}" for b in self._buffer)

    def dump_hexdump(self, bytes_per_line: int = 16) -> str:
        """Format buffer as classic Wireshark/tcpdump hex and ASCII dump."""
        lines = []
        for i in range(0, len(self._buffer), bytes_per_line):
            chunk = self._buffer[i:i + bytes_per_line]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            padding = "   " * (bytes_per_line - len(chunk))
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}:  {hex_part}{padding}  |{ascii_part}|")
        return "\\n".join(lines)

    @property
    def length(self) -> int:
        return len(self._buffer)

    def __len__(self) -> int:
        return len(self._buffer)

    @property
    def cursor(self) -> int:
        return self._cursor

    @cursor.setter
    def cursor(self, position: int):
        if not 0 <= position <= len(self._buffer):
            raise ValueError(f"Cursor out of bounds: {position} (buffer len: {len(self._buffer)})")
        self._cursor = position

    @property
    def remaining(self) -> int:
        return max(0, len(self._buffer) - self._cursor)

    def has_remaining(self, count: int = 1) -> bool:
        return self.remaining >= count

    def reset(self) -> None:
        self._cursor = 0

    def clear(self) -> None:
        self._buffer.clear()
        self._cursor = 0

    def to_bytes(self) -> bytes:
        return bytes(self._buffer)

    def to_bytearray(self) -> bytearray:
        return bytearray(self._buffer)

    # --- Read Operations (Big Endian Network Order) ---

    def read_bytes(self, count: int) -> bytes:
        if self._cursor + count > len(self._buffer):
            raise IndexError(f"Buffer underflow reading {count} bytes at cursor {self._cursor}")
        val = bytes(self._buffer[self._cursor:self._cursor + count])
        self._cursor += count
        return val

    def peek_bytes(self, count: int) -> bytes:
        if self._cursor + count > len(self._buffer):
            raise IndexError(f"Buffer underflow peeking {count} bytes at cursor {self._cursor}")
        return bytes(self._buffer[self._cursor:self._cursor + count])

    def read_uint8(self) -> int:
        if self._cursor >= len(self._buffer):
            raise IndexError("Buffer underflow reading uint8")
        val = self._buffer[self._cursor]
        self._cursor += 1
        return val

    def read_int8(self) -> int:
        u = self.read_uint8()
        return u if u < 128 else u - 256

    def read_uint16_be(self) -> int:
        raw = self.read_bytes(2)
        return struct.unpack("!H", raw)[0]

    def read_uint16_le(self) -> int:
        raw = self.read_bytes(2)
        return struct.unpack("<H", raw)[0]

    def read_int16_be(self) -> int:
        raw = self.read_bytes(2)
        return struct.unpack("!h", raw)[0]

    def read_uint24_be(self) -> int:
        raw = self.read_bytes(3)
        return (raw[0] << 16) | (raw[1] << 8) | raw[2]

    def read_uint32_be(self) -> int:
        raw = self.read_bytes(4)
        return struct.unpack("!I", raw)[0]

    def read_uint32_le(self) -> int:
        raw = self.read_bytes(4)
        return struct.unpack("<I", raw)[0]

    def read_int32_be(self) -> int:
        raw = self.read_bytes(4)
        return struct.unpack("!i", raw)[0]

    def read_uint64_be(self) -> int:
        raw = self.read_bytes(8)
        return struct.unpack("!Q", raw)[0]

    def read_int64_be(self) -> int:
        raw = self.read_bytes(8)
        return struct.unpack("!q", raw)[0]

    def read_varint(self) -> Tuple[int, int]:
        """Read Protobuf / QUIC style variable-length integer (returns val, bytes_read)."""
        result = 0
        shift = 0
        read_count = 0
        while True:
            b = self.read_uint8()
            read_count += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift >= 64:
                raise ValueError("Varint exceeds 64-bit integer")
        return result, read_count

    # --- Write Operations (Big Endian Network Order) ---

    def write_bytes(self, data: Union[bytes, bytearray, List[int]]) -> PacketBuffer:
        self._buffer.extend(data)
        return self

    def write_uint8(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 255:
            raise ValueError(f"Value out of uint8 range: {val}")
        self._buffer.append(val)
        return self

    def write_int8(self, val: int) -> PacketBuffer:
        if not -128 <= val <= 127:
            raise ValueError(f"Value out of int8 range: {val}")
        self._buffer.append(val if val >= 0 else val + 256)
        return self

    def write_uint16_be(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 65535:
            raise ValueError(f"Value out of uint16 range: {val}")
        self._buffer.extend(struct.pack("!H", val))
        return self

    def write_uint16_le(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 65535:
            raise ValueError(f"Value out of uint16 range: {val}")
        self._buffer.extend(struct.pack("<H", val))
        return self

    def write_int16_be(self, val: int) -> PacketBuffer:
        self._buffer.extend(struct.pack("!h", val))
        return self

    def write_uint24_be(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 0xFFFFFF:
            raise ValueError(f"Value out of uint24 range: {val}")
        self._buffer.append((val >> 16) & 0xFF)
        self._buffer.append((val >> 8) & 0xFF)
        self._buffer.append(val & 0xFF)
        return self

    def write_uint32_be(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 0xFFFFFFFF:
            raise ValueError(f"Value out of uint32 range: {val}")
        self._buffer.extend(struct.pack("!I", val))
        return self

    def write_uint32_le(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 0xFFFFFFFF:
            raise ValueError(f"Value out of uint32 range: {val}")
        self._buffer.extend(struct.pack("<I", val))
        return self

    def write_int32_be(self, val: int) -> PacketBuffer:
        self._buffer.extend(struct.pack("!i", val))
        return self

    def write_uint64_be(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"Value out of uint64 range: {val}")
        self._buffer.extend(struct.pack("!Q", val))
        return self

    def write_int64_be(self, val: int) -> PacketBuffer:
        self._buffer.extend(struct.pack("!q", val))
        return self

    def write_varint(self, val: int) -> PacketBuffer:
        """Write integer encoded as variable-length protobuf style integer."""
        if val < 0:
            raise ValueError(f"Varint must be non-negative, got {val}")
        while True:
            byte = val & 0x7F
            val >>= 7
            if val > 0:
                self._buffer.append(byte | 0x80)
            else:
                self._buffer.append(byte)
                break
        return self

    def insert_at(self, index: int, data: Union[bytes, bytearray]) -> None:
        """Insert raw bytes at specific index."""
        self._buffer[index:index] = data

    def overwrite_at(self, index: int, data: Union[bytes, bytearray]) -> None:
        """Overwrite bytes starting at specific index."""
        end = index + len(data)
        if end > len(self._buffer):
            raise IndexError("Overwrite exceeds buffer length")
        self._buffer[index:end] = data

    def slice(self, start: int, length: Optional[int] = None) -> PacketBuffer:
        """Return a new PacketBuffer containing a subslice."""
        end = len(self._buffer) if length is None else start + length
        return PacketBuffer(self._buffer[start:end])
'''
    total_lines += write_code_file("netsphere/core/buffer.py", content_buffer)

    # netsphere/core/bitfield.py
    content_bitfield = '''"""
Bitfield packing and unpacking utilities for protocol headers.
"""
from typing import Dict, Any, List, Tuple


class BitMask:
    """Computes and stores integer bitmasks."""
    @staticmethod
    def mask(width: int) -> int:
        """Generate a bitmask of given bit width: width 4 -> 0b1111 (0xF)."""
        if width <= 0:
            return 0
        return (1 << width) - 1

    @staticmethod
    def get_bits(value: int, offset: int, width: int) -> int:
        """Extract 'width' bits from 'value' at bit position 'offset' (from LSB)."""
        return (value >> offset) & BitMask.mask(width)

    @staticmethod
    def set_bits(target: int, value: int, offset: int, width: int) -> int:
        """Set 'width' bits in 'target' at 'offset' to 'value'."""
        clean_val = value & BitMask.mask(width)
        mask = BitMask.mask(width) << offset
        return (target & ~mask) | (clean_val << offset)


class BitField:
    """Represents a bitfield descriptor within a composite protocol integer."""
    def __init__(self, name: str, width: int, offset: int, description: str = ""):
        self.name = name
        self.width = width
        self.offset = offset
        self.description = description

    def extract(self, integer_val: int) -> int:
        return BitMask.get_bits(integer_val, self.offset, self.width)

    def pack(self, target_int: int, value: int) -> int:
        return BitMask.set_bits(target_int, value, self.offset, self.width)


def extract_bits(value: int, offset: int, width: int) -> int:
    return BitMask.get_bits(value, offset, width)


def pack_bits(target: int, value: int, offset: int, width: int) -> int:
    return BitMask.set_bits(target, value, offset, width)


class CompositeBitfield:
    """
    Helper for multi-field bit structures (e.g. IPv4 Version + IHL, TCP Data Offset + Flags).
    """
    def __init__(self, total_bits: int, fields: List[Tuple[str, int]]):
        """
        fields: list of (field_name, bit_width) ordered from MSB to LSB.
        """
        self.total_bits = total_bits
        self.fields: Dict[str, BitField] = {}
        current_offset = total_bits
        for name, width in fields:
            current_offset -= width
            self.fields[name] = BitField(name, width, current_offset)
        if current_offset != 0:
            raise ValueError(f"Total bit width mismatch: expected {total_bits}, remaining {current_offset}")

    def decode(self, raw_integer: int) -> Dict[str, int]:
        result = {}
        for name, bf in self.fields.items():
            result[name] = bf.extract(raw_integer)
        return result

    def encode(self, values: Dict[str, int]) -> int:
        packed = 0
        for name, bf in self.fields.items():
            val = values.get(name, 0)
            packed = bf.pack(packed, val)
        return packed
'''
    total_lines += write_code_file("netsphere/core/bitfield.py", content_bitfield)

    # netsphere/core/checksum.py
    content_checksum = '''"""
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
'''
    total_lines += write_code_file("netsphere/core/checksum.py", content_checksum)

    # netsphere/core/events.py
    content_events = '''"""
Internal Asynchronous Event Bus and Network Telemetry Event Definitions.
"""
from __future__ import annotations
import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Any, Optional
from netsphere.core.types import PacketDirection


@dataclass
class Event:
    """Base network event object."""
    event_type: str
    timestamp: float = field(default_factory=time.time)
    source: str = "netsphere"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PacketReceivedEvent(Event):
    """Triggered when an interface receives a packet."""
    interface_name: str = ""
    direction: PacketDirection = PacketDirection.INGRESS
    packet_length: int = 0
    protocol: str = ""
    summary: str = ""


@dataclass
class PacketDroppedEvent(Event):
    """Triggered when a packet is dropped due to buffer overflow, TTL, or firewall rule."""
    interface_name: str = ""
    reason: str = ""
    packet_length: int = 0


@dataclass
class InterfaceStateChangeEvent(Event):
    """Triggered when an interface goes up, down, or changes duplex/speed."""
    interface_name: str = ""
    old_state: str = ""
    new_state: str = ""


@dataclass
class RouteAddedEvent(Event):
    """Triggered when routing table adds a new prefix."""
    prefix: str = ""
    next_hop: str = ""
    metric: int = 0


@dataclass
class AnomalyAlertEvent(Event):
    """Triggered when traffic analysis detects a network security threat."""
    threat_type: str = ""
    severity: str = "HIGH"
    target_ip: str = ""
    description: str = ""


class EventBus:
    """
    Thread-safe synchronous and asynchronous event dispatching bus.
    """
    def __init__(self, max_history: int = 1000):
        self._listeners: Dict[str, List[Callable[[Event], None]]] = {}
        self._lock = threading.Lock()
        self._history: List[Event] = []
        self._max_history = max_history

    def subscribe(self, event_type: str, callback: Callable[[Event], None]) -> None:
        """Subscribe a callable to a specific event type, or '*' for all events."""
        with self._lock:
            if event_type not in self._listeners:
                self._listeners[event_type] = []
            self._listeners[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable[[Event], None]) -> None:
        with self._lock:
            if event_type in self._listeners and callback in self._listeners[event_type]:
                self._listeners[event_type].remove(callback)

    def publish(self, event: Event) -> None:
        """Dispatch event synchronously to all registered subscribers."""
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history.pop(0)

            # Targeted listeners
            callbacks = list(self._listeners.get(event.event_type, []))
            # Wildcard listeners
            wildcard_callbacks = list(self._listeners.get("*", []))

        for cb in callbacks + wildcard_callbacks:
            try:
                cb(event)
            except Exception as e:
                # Event dispatch should not crash publisher
                print(f"[EventBus] Error in callback {cb}: {e}")

    def get_history(self, limit: Optional[int] = None) -> List[Event]:
        with self._lock:
            if limit is None:
                return list(self._history)
            return list(self._history[-limit:])

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()


# Default singleton instance for global event bus
global_event_bus = EventBus()
'''
    total_lines += write_code_file("netsphere/core/events.py", content_events)

    print(f"[*] Completed Core generation: {total_lines:,} LOC")
    return total_lines

if __name__ == "__main__":
    generate_core()
