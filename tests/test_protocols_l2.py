"""Unit tests for Layer 2 Protocols (Ethernet, ARP, VLAN, STP, LLDP)."""
import unittest
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import MACAddress, IPv4Address, EtherType
from netsphere.protocols.l2.ethernet import EthernetHeader, EthernetFrame
from netsphere.protocols.l2.arp import ARPHeader, ARPOperation
from netsphere.protocols.l2.vlan import VLANHeader, QinQHeader
from netsphere.protocols.l2.stp import STPHeader, BPDUType
from netsphere.protocols.l2.lldp import LLDPHeader, LLDPTLV, LLDPTLVType


class TestLayer2Protocols(unittest.TestCase):
    def test_ethernet_header_pack_unpack(self):
        dst = MACAddress("00:0c:29:4f:8e:35")
        src = MACAddress("00:50:56:c0:00:08")
        hdr = EthernetHeader(dst_mac=dst, src_mac=src, ethertype=EtherType.IPV4)
        packed = hdr.pack()
        self.assertEqual(len(packed), 14)

        unpacked = EthernetHeader.unpack(PacketBuffer(packed))
        self.assertEqual(str(unpacked.dst_mac), str(dst))
        self.assertEqual(str(unpacked.src_mac), str(src))
        self.assertEqual(unpacked.ethertype, EtherType.IPV4)

    def test_arp_pack_unpack(self):
        s_mac = MACAddress("00:11:22:33:44:55")
        s_ip = IPv4Address("192.168.1.10")
        t_mac = MACAddress("00:00:00:00:00:00")
        t_ip = IPv4Address("192.168.1.1")

        arp = ARPHeader(
            operation=ARPOperation.REQUEST,
            sender_mac=s_mac,
            sender_ip=s_ip,
            target_mac=t_mac,
            target_ip=t_ip,
        )
        packed = arp.pack()
        self.assertEqual(len(packed), 28)

        unpacked = ARPHeader.unpack(PacketBuffer(packed))
        self.assertEqual(unpacked.operation, ARPOperation.REQUEST)
        self.assertEqual(str(unpacked.sender_ip), "192.168.1.10")
        self.assertEqual(str(unpacked.target_ip), "192.168.1.1")

    def test_vlan_8021q(self):
        vlan = VLANHeader(vlan_id=100, priority=3, next_ethertype=EtherType.IPV4)
        packed = vlan.pack()
        self.assertEqual(len(packed), 4)

        unpacked = VLANHeader.unpack(PacketBuffer(packed))
        self.assertEqual(unpacked.vlan_id, 100)
        self.assertEqual(unpacked.priority, 3)
        self.assertEqual(unpacked.next_ethertype, EtherType.IPV4)

    def test_stp_bpdu(self):
        stp = STPHeader(bpdu_type=BPDUType.CONFIGURATION, root_priority=32768)
        packed = stp.pack()
        self.assertEqual(len(packed), 35)

        unpacked = STPHeader.unpack(PacketBuffer(packed))
        self.assertEqual(unpacked.bpdu_type, BPDUType.CONFIGURATION)
        self.assertEqual(unpacked.root_priority, 32768)

    def test_lldp(self):
        chassis_tlv = LLDPTLV(LLDPTLVType.CHASSIS_ID, b"\x04\x00\x11\x22\x33\x44\x55")
        port_tlv = LLDPTLV(LLDPTLVType.PORT_ID, b"\x03eth0")
        end_tlv = LLDPTLV(LLDPTLVType.END_OF_LLDPDU, b"")
        lldp = LLDPHeader([chassis_tlv, port_tlv, end_tlv])
        packed = lldp.pack()

        unpacked = LLDPHeader.unpack(PacketBuffer(packed))
        self.assertEqual(len(unpacked.tlvs), 3)


if __name__ == "__main__":
    unittest.main()
