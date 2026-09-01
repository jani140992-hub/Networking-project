"""Unit tests for NetSphere SNMP Agent."""
import unittest
from netsphere.protocols.l7.snmp_agent import SNMPAgent


class TestSNMPAgent(unittest.TestCase):
    def setUp(self):
        self.agent = SNMPAgent(sys_descr="Core Switch", sys_contact="admin@net.org")

    def test_snmp_get(self):
        val = self.agent.get("1.3.6.1.2.1.1.1.0")
        self.assertEqual(val, "Core Switch")

    def test_snmp_walk(self):
        system_objects = self.agent.walk("1.3.6.1.2.1.1")
        self.assertGreaterEqual(len(system_objects), 6)

    def test_snmp_set(self):
        self.agent.set("1.3.6.1.2.1.1.5.0", "new-hostname")
        self.assertEqual(self.agent.get("1.3.6.1.2.1.1.5.0"), "new-hostname")


if __name__ == "__main__":
    unittest.main()
