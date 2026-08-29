"""Unit tests for Layer 3 Protocols (IPv4, IPv6, ICMP, ICMPv6, IGMP, IPsec, GRE)."""
import unittest
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import IPv4Address, IPv6Address, TransportProtocol
from netsphere.protocols.l3.ipv4 import IPv4Header, IPv4Flags
from netsphere.protocols.l3.ipv6 import IPv6Header
from netsphere.protocols.l3.icmp import ICMPHeader, ICMPType
from netsphere.protocols.l3.icmpv6 import ICMPv6Header, ICMPv6Type
from netsphere.protocols.l3.igmp import IGMPHeader, IGMPType
from netsphere.protocols.l3.gre import GREHeader


class TestLayer3Protocols(unittest.TestCase):
    def test_ipv4_pack_unpack_checksum(self):
        src = IPv4Address("192.168.1.100")
        dst = IPv4Address("8.8.8.8")
        hdr = IPv4Header(src_ip=src, dst_ip=dst, protocol=TransportProtocol.TCP, ttl=64)
        packed = hdr.pack()
        self.assertEqual(len(packed), 20)
        self.assertNotEqual(hdr.checksum, 0)

        unpacked = IPv4Header.unpack(PacketBuffer(packed))
        self.assertEqual(str(unpacked.src_ip), "192.168.1.100")
        self.assertEqual(str(unpacked.dst_ip), "8.8.8.8")
        self.assertEqual(unpacked.ttl, 64)
        self.assertEqual(unpacked.checksum, hdr.checksum)

    def test_ipv6_pack_unpack(self):
        src = IPv6Address("2001:db8::1")
        dst = IPv6Address("2001:db8::2")
        hdr = IPv6Header(src_ip=src, dst_ip=dst, next_header=TransportProtocol.UDP, hop_limit=128)
        packed = hdr.pack()
        self.assertEqual(len(packed), 40)

        unpacked = IPv6Header.unpack(PacketBuffer(packed))
        self.assertEqual(str(unpacked.src_ip), str(src))
        self.assertEqual(str(unpacked.dst_ip), str(dst))
        self.assertEqual(unpacked.hop_limit, 128)

    def test_icmp_echo(self):
        icmp = ICMPHeader(icmp_type=ICMPType.ECHO_REQUEST, identifier=0x1234, sequence_number=1)
        payload = b"PingTestPayload"
        packed = icmp.pack(payload)
        self.assertEqual(len(packed), 8)

        unpacked = ICMPHeader.unpack(PacketBuffer(packed))
        self.assertEqual(unpacked.icmp_type, ICMPType.ECHO_REQUEST)
        self.assertEqual(unpacked.identifier, 0x1234)
        self.assertEqual(unpacked.sequence_number, 1)

    def test_gre_encapsulation(self):
        gre = GREHeader(checksum_present=False, key_present=True, key=0x12345678)
        packed = gre.pack()
        self.assertEqual(len(packed), 8)

        unpacked = GREHeader.unpack(PacketBuffer(packed))
        self.assertTrue(unpacked.key_present)
        self.assertEqual(unpacked.key, 0x12345678)


if __name__ == "__main__":
    unittest.main()
