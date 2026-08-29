"""
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
        return self.raw_bytes == b"\xff\xff\xff\xff\xff\xff"

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
        return cls(b"\xff\xff\xff\xff\xff\xff")

    @classmethod
    def zero(cls) -> MACAddress:
        return cls(b"\x00\x00\x00\x00\x00\x00")


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
        return self.packed == b"\xff\xff\xff\xff"

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
        return self.packed == (b"\x00" * 15 + b"\x01")

    @property
    def is_unspecified(self) -> bool:
        return self.packed == (b"\x00" * 16)

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
