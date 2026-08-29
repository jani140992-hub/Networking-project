"""Unit tests for Layer 4 Protocols (TCP, TCP State Machine, UDP, SCTP)."""
import unittest
from netsphere.core.buffer import PacketBuffer
from netsphere.core.types import Port, IPv4Address
from netsphere.protocols.l4.tcp import TCPHeader, TCPFlags, TCPOption
from netsphere.protocols.l4.tcp_state import TCPConnection, TCPState, RTTTracker
from netsphere.protocols.l4.udp import UDPHeader
from netsphere.protocols.l4.sctp import SCTPHeader, SCTPChunk, SCTPChunkType


class TestLayer4Protocols(unittest.TestCase):
    def test_tcp_header_and_options(self):
        hdr = TCPHeader(
            src_port=Port(54321),
            dst_port=Port(443),
            seq_num=1000,
            ack_num=0,
            flags=TCPFlags(syn=True),
            options=[TCPOption.mss(1460), TCPOption.sack_permitted()],
        )
        src_ip = IPv4Address("192.168.1.5").packed
        dst_ip = IPv4Address("1.1.1.1").packed
        packed = hdr.pack(src_ip=src_ip, dst_ip=dst_ip)
        self.assertTrue(len(packed) >= 24)

        unpacked = TCPHeader.unpack(PacketBuffer(packed))
        self.assertEqual(int(unpacked.src_port), 54321)
        self.assertEqual(int(unpacked.dst_port), 443)
        self.assertTrue(unpacked.flags.syn)
        self.assertEqual(len(unpacked.options), 2)

    def test_tcp_three_way_handshake(self):
        # Client side: sends SYN -> SYN_SENT
        client = TCPConnection(local_port=50000, remote_port=80, initial_seq=100)
        client.state = TCPState.SYN_SENT

        # Server side receives SYN -> SYN_RCVD, returns SYN-ACK
        server = TCPConnection(local_port=80, remote_port=50000, initial_seq=500)
        server.state = TCPState.LISTEN

        syn_pkt = TCPHeader(src_port=Port(50000), dst_port=Port(80), seq_num=100, flags=TCPFlags(syn=True))
        syn_ack_resp = server.handle_segment(syn_pkt)
        self.assertEqual(server.state, TCPState.SYN_RCVD)
        self.assertIsNotNone(syn_ack_resp)
        self.assertTrue(syn_ack_resp.flags.syn and syn_ack_resp.flags.ack)

        # Client receives SYN-ACK -> returns ACK -> ESTABLISHED
        ack_resp = client.handle_segment(syn_ack_resp)
        self.assertEqual(client.state, TCPState.ESTABLISHED)
        self.assertIsNotNone(ack_resp)
        self.assertTrue(ack_resp.flags.ack)

        # Server receives final ACK -> ESTABLISHED
        server.handle_segment(ack_resp)
        self.assertEqual(server.state, TCPState.ESTABLISHED)

    def test_rto_tracker(self):
        rtt = RTTTracker(initial_rto=1.0)
        rtt.update(0.05) # 50ms measurement
        self.assertIsNotNone(rtt.srtt)
        self.assertTrue(0.04 <= rtt.srtt <= 0.06)
        self.assertTrue(rtt.rto >= rtt.min_rto)

    def test_udp_pack_unpack(self):
        udp = UDPHeader(src_port=Port(12345), dst_port=Port(53), length=8)
        packed = udp.pack()
        self.assertEqual(len(packed), 8)

        unpacked = UDPHeader.unpack(PacketBuffer(packed))
        self.assertEqual(int(unpacked.src_port), 12345)
        self.assertEqual(int(unpacked.dst_port), 53)


if __name__ == "__main__":
    unittest.main()
