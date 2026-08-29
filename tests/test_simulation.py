"""Unit tests for NetSphere Simulation (LPM Trie, Switch, Router, NAT, QoS, Congestion)."""
import unittest
from netsphere.core.types import IPv4Address, MACAddress
from netsphere.simulation.trie import LPMTrie
from netsphere.simulation.switch import VirtualSwitch, PortMode
from netsphere.simulation.router import VirtualRouter
from netsphere.simulation.nat import NATEngine
from netsphere.simulation.routing import NetworkGraph, dijkstra_shortest_path
from netsphere.simulation.qos import TokenBucketFilter, LeakyBucketFilter
from netsphere.simulation.congestion import TCPTahoeModel, TCPRenoModel, TCPCubicModel
from netsphere.protocols.l3.ipv4 import IPv4Header


class TestSimulationComponents(unittest.TestCase):
    def test_lpm_trie(self):
        trie = LPMTrie()
        trie.insert("10.0.0.0/8", "Hop-10")
        trie.insert("10.1.0.0/16", "Hop-10.1")
        trie.insert("10.1.1.0/24", "Hop-10.1.1")
        trie.insert("0.0.0.0/0", "Default-Gateway")

        prefix, val = trie.lookup("10.1.1.55")
        self.assertEqual(val, "Hop-10.1.1")

        prefix, val = trie.lookup("10.1.2.99")
        self.assertEqual(val, "Hop-10.1")

        prefix, val = trie.lookup("192.168.1.1")
        self.assertEqual(val, "Default-Gateway")

    def test_virtual_switch_learning(self):
        sw = VirtualSwitch("sw1")
        sw.add_port("eth0", PortMode.ACCESS, default_vlan=10)
        sw.add_port("eth1", PortMode.ACCESS, default_vlan=10)

        # Ingress frame on eth0: Src MAC A, Dst MAC Broadcast
        frame_bytes = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00Payload"
        forwarded = sw.process_frame("eth0", frame_bytes)
        # Should flood to eth1
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0][0], "eth1")

        # Now send unicast back to MAC A from eth1
        reply_frame = b"\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee\x08\x00Reply"
        forwarded_reply = sw.process_frame("eth1", reply_frame)
        # Should forward directly to eth0 (unicast hit)
        self.assertEqual(len(forwarded_reply), 1)
        self.assertEqual(forwarded_reply[0][0], "eth0")

    def test_dijkstra_shortest_path(self):
        graph = NetworkGraph()
        graph.add_edge("A", "B", 1.0)
        graph.add_edge("B", "C", 2.0)
        graph.add_edge("A", "C", 5.0)

        distances, previous = dijkstra_shortest_path(graph, "A")
        self.assertEqual(distances["C"], 3.0)
        self.assertEqual(previous["C"], "B")

    def test_nat_engine(self):
        nat = NATEngine(public_ip=IPv4Address("203.0.113.1"))
        from netsphere.core.types import Port
        ext_ip, ext_port = nat.translate_outbound(
            src_ip=IPv4Address("192.168.1.10"),
            src_port=Port(12345),
            dst_ip=IPv4Address("8.8.8.8"),
            dst_port=Port(53),
            protocol=17,
        )
        self.assertEqual(str(ext_ip), "203.0.113.1")

        # Reverse lookup
        res = nat.translate_inbound(
            dst_port=ext_port,
            remote_ip=IPv4Address("8.8.8.8"),
            remote_port=Port(53),
            protocol=17,
        )
        self.assertIsNotNone(res)
        int_ip, int_port = res
        self.assertEqual(str(int_ip), "192.168.1.10")
        self.assertEqual(int(int_port), 12345)

    def test_token_bucket(self):
        tbf = TokenBucketFilter(rate_bytes_sec=1000, burst_bytes=500)
        self.assertTrue(tbf.consume(200))
        self.assertTrue(tbf.consume(300))
        self.assertFalse(tbf.consume(100)) # Exceeded bucket


if __name__ == "__main__":
    unittest.main()
