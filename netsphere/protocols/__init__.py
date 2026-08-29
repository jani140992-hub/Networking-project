"""
NetSphere Protocol Engineering & Dissection Engine.
Encapsulates OSI L2 through L7 protocol dissectors, serializers, and validators.
"""
from netsphere.protocols.base import (
    ProtocolHeader,
    Packet,
    ProtocolDissector,
    DissectionError,
    ProtocolRegistry,
)

__all__ = [
    "ProtocolHeader",
    "Packet",
    "ProtocolDissector",
    "DissectionError",
    "ProtocolRegistry",
]
