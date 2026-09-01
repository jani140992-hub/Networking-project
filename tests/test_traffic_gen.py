"""Unit tests for NetSphere Synthetic Traffic Generator."""
import unittest
from netsphere.simulation.traffic_gen import SyntheticTrafficGenerator, TrafficProfile


class TestTrafficGen(unittest.TestCase):
    def test_packet_generation(self):
        gen = SyntheticTrafficGenerator(
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            packet_size=256,
            rate_pps=50,
        )
        packet = gen.generate_packet()
        wire_data = packet.pack()
        self.assertEqual(len(wire_data), 256)
        self.assertEqual(gen.packets_generated, 1)

    def test_batch_stream(self):
        gen = SyntheticTrafficGenerator(packet_size=128)
        batch = gen.stream_batch(10)
        self.assertEqual(len(batch), 10)
        self.assertEqual(gen.packets_generated, 10)


if __name__ == "__main__":
    unittest.main()
