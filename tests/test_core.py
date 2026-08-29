"""Unit tests for NetSphere Core primitives."""
import unittest
from netsphere.core.buffer import PacketBuffer
from netsphere.core.bitfield import extract_bits, pack_bits, BitMask
from netsphere.core.checksum import (
    calculate_internet_checksum,
    calculate_crc32,
    calculate_crc16,
    calculate_adler32,
    compute_pseudo_header_checksum,
)
from netsphere.core.types import (
    MACAddress,
    IPv4Address,
    IPv6Address,
    CIDRNetwork,
    Port,
    ProtocolNumber,
    SubnetMask,
)
from netsphere.core.events import EventBus, Event


class TestCorePrimitives(unittest.TestCase):
    def test_mac_address(self):
        mac = MACAddress("00:50:56:C0:00:08")
        self.assertEqual(str(mac), "00:50:56:c0:00:08")
        self.assertTrue(mac.is_unicast)
        self.assertFalse(mac.is_multicast)
        self.assertEqual(mac.oui, "00:50:56")

        bcast = MACAddress.broadcast()
        self.assertTrue(bcast.is_broadcast)
        self.assertTrue(bcast.is_multicast)

    def test_ipv4_address(self):
        ip = IPv4Address("192.168.1.1")
        self.assertEqual(str(ip), "192.168.1.1")
        self.assertTrue(ip.is_private)
        self.assertFalse(ip.is_loopback)

        loop = IPv4Address.loopback()
        self.assertTrue(loop.is_loopback)

    def test_cidr_network(self):
        net = CIDRNetwork("192.168.1.0/24")
        self.assertEqual(str(net.netmask), "255.255.255.0")
        self.assertEqual(str(net.broadcast_address), "192.168.1.255")
        self.assertEqual(net.num_usable_hosts, 254)
        self.assertTrue("192.168.1.50" in net)
        self.assertFalse("192.168.2.1" in net)

    def test_packet_buffer(self):
        buf = PacketBuffer()
        buf.write_uint8(0x45)
        buf.write_uint16_be(0x1234)
        buf.write_uint32_be(0xAABBCCDD)
        self.assertEqual(len(buf), 7)

        buf.reset()
        self.assertEqual(buf.read_uint8(), 0x45)
        self.assertEqual(buf.read_uint16_be(), 0x1234)
        self.assertEqual(buf.read_uint32_be(), 0xAABBCCDD)

    def test_bitfields(self):
        val = 0
        val = pack_bits(val, 4, 4, 4) # Version 4
        val = pack_bits(val, 5, 0, 4) # IHL 5
        self.assertEqual(val, 0x45)
        self.assertEqual(extract_bits(val, 4, 4), 4)
        self.assertEqual(extract_bits(val, 0, 4), 5)

    def test_checksums(self):
        data = b"Hello, NetSphere!"
        csum = calculate_internet_checksum(data)
        self.assertIsInstance(csum, int)
        self.assertTrue(0 <= csum <= 0xFFFF)

        crc = calculate_crc32(data)
        self.assertIsInstance(crc, int)

    def test_event_bus(self):
        bus = EventBus()
        received = []

        def handler(evt):
            received.append(evt)

        bus.subscribe("packet.rx", handler)
        bus.publish(Event(event_type="packet.rx", metadata={"len": 64}))
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].metadata["len"], 64)


if __name__ == "__main__":
    unittest.main()
