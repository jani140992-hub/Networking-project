"""Unit tests for Topology Synchronization Engine."""
import unittest
from netsphere.simulation.topology import NetworkTopology, NodeType
from netsphere.simulation.topology_sync import TopologySyncEngine


class TestTopologySync(unittest.TestCase):
    def test_sync_snapshot_and_metrics(self):
        topo = NetworkTopology("DC-Core")
        topo.add_node("r1", NodeType.ROUTER, "Core-RTR", 100, 100)
        topo.add_node("s1", NodeType.SWITCH, "Access-SW", 100, 200)
        topo.add_link("l1", "r1", "eth0", "s1", "g0/1")

        engine = TopologySyncEngine(topo)
        snapshot = engine.snapshot()
        self.assertEqual(len(snapshot["nodes"]), 2)
        self.assertEqual(len(snapshot["links"]), 1)

        prom = engine.export_prometheus_metrics()
        self.assertIn("netsphere_nodes_total 2", prom)
        self.assertIn("netsphere_links_total 1", prom)


if __name__ == "__main__":
    unittest.main()
