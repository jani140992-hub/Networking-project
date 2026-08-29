"""Unit tests for NetSphere Standards Catalogs."""
import unittest
from netsphere.catalog.ports import lookup_port, PORT_DIRECTORY
from netsphere.catalog.protocols import lookup_protocol, IP_PROTOCOL_DIRECTORY
from netsphere.catalog.mibs import lookup_oid, MIB_TREE
from netsphere.catalog.oui import lookup_oui, OUI_DIRECTORY
from netsphere.catalog.rfc import lookup_rfc, RFC_CATALOG


class TestCatalogRegistries(unittest.TestCase):
    def test_ports_catalog(self):
        p80 = lookup_port(80)
        self.assertIsNotNone(p80)
        self.assertEqual(p80.service, "http")

        p443 = lookup_port(443)
        self.assertIsNotNone(p443)
        self.assertEqual(p443.service, "https")

        self.assertTrue(len(PORT_DIRECTORY) >= 2000)

    def test_protocols_catalog(self):
        tcp = lookup_protocol(6)
        self.assertIsNotNone(tcp)
        self.assertEqual(tcp.keyword, "TCP")

        udp = lookup_protocol(17)
        self.assertIsNotNone(udp)
        self.assertEqual(udp.keyword, "UDP")

    def test_mibs_catalog(self):
        sys_descr = lookup_oid("1.3.6.1.2.1.1.1.0")
        self.assertIsNotNone(sys_descr)
        self.assertEqual(sys_descr.name, "sysDescr")

    def test_oui_catalog(self):
        vmware = lookup_oui("00:50:56:00:11:22")
        self.assertIsNotNone(vmware)
        self.assertTrue("VMware" in vmware.vendor)

    def test_rfc_catalog(self):
        rfc793 = lookup_rfc(793)
        self.assertIsNotNone(rfc793)
        self.assertTrue("Transmission Control Protocol" in rfc793.title)


if __name__ == "__main__":
    unittest.main()
