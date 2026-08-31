"""Unit tests for NetSphere Packet Filter."""
import unittest
from netsphere.protocols.base import Packet
from netsphere.protocols.l2.ethernet import EthernetHeader
from netsphere.protocols.l3.ipv4 import IPv4Header
from netsphere.protocols.l4.tcp import TCPHeader, TCPFlags
from netsphere.core.types import MACAddress, IPv4Address, Port, EtherType, TransportProtocol
from netsphere.simulation.filter import PacketFilter


class TestPacketFilter(unittest.TestCase):
    def setUp(self):
        self.eth = EthernetHeader(
            dst_mac=MACAddress("00:0c:29:4f:8e:35"),
            src_mac=MACAddress("00:50:56:c0:00:08"),
            ethertype=EtherType.IPV4,
        )
        self.ip = IPv4Header(
            src_ip=IPv4Address("192.168.1.100"),
            dst_ip=IPv4Address("10.0.0.1"),
            protocol=TransportProtocol.TCP,
            ttl=64,
        )
        self.tcp = TCPHeader(
            src_port=Port(54321),
            dst_port=Port(80),
            seq_num=100,
            flags=TCPFlags(syn=True),
        )
        self.packet = Packet(headers=[self.eth, self.ip, self.tcp], payload=b"GET / HTTP/1.1\r\n\r\n")

    def test_filter_matching(self):
        f1 = PacketFilter("tcp")
        self.assertTrue(f1.matches(self.packet))

        f2 = PacketFilter("tcp.dstport == 80")
        self.assertTrue(f2.matches(self.packet))

        f3 = PacketFilter("ip.src == 192.168.1.100 and tcp.dstport == 80")
        self.assertTrue(f3.matches(self.packet))

        f4 = PacketFilter("tcp.dstport == 443")
        self.assertFalse(f4.matches(self.packet))


if __name__ == "__main__":
    unittest.main()
