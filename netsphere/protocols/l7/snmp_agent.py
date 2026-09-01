"""
NetSphere SNMP Agent & MIB Object Provider.
Handles SNMP GET, GETNEXT requests against system and interface MIBs.
"""
from __future__ import annotations
from typing import Dict, Any, Optional, Tuple, List
from netsphere.catalog.mibs import MIB_TREE, lookup_oid


class SNMPAgent:
    """Lightweight SNMPv2c management agent."""
    def __init__(self, sys_descr: str = "NetSphere Edge Router v1.0", sys_contact: str = "noc@netsphere.io"):
        self.mib_store: Dict[str, Any] = {
            "1.3.6.1.2.1.1.1.0": sys_descr,           # sysDescr
            "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.99999", # sysObjectID
            "1.3.6.1.2.1.1.3.0": 1234567,              # sysUpTime (hundredths of a second)
            "1.3.6.1.2.1.1.4.0": sys_contact,         # sysContact
            "1.3.6.1.2.1.1.5.0": "core-router-01",     # sysName
            "1.3.6.1.2.1.1.6.0": "DataCenter-1-Rack3",# sysLocation
            "1.3.6.1.2.1.2.1.0": 4,                    # ifNumber
        }

    def get(self, oid: str) -> Optional[Any]:
        """Perform SNMP GET for a specific OID."""
        return self.mib_store.get(oid)

    def get_next(self, oid: str) -> Optional[Tuple[str, Any]]:
        """Perform SNMP GETNEXT finding the lexicographically next OID."""
        sorted_oids = sorted(self.mib_store.keys())
        for existing in sorted_oids:
            if existing > oid:
                return existing, self.mib_store[existing]
        return None

    def walk(self, root_oid: str) -> List[Tuple[str, Any]]:
        """Perform SNMP walk from a root OID prefix."""
        results = []
        for oid in sorted(self.mib_store.keys()):
            if oid.startswith(root_oid):
                results.append((oid, self.mib_store[oid]))
        return results

    def set(self, oid: str, value: Any) -> bool:
        """Perform SNMP SET updating a value in MIB store."""
        self.mib_store[oid] = value
        return True
