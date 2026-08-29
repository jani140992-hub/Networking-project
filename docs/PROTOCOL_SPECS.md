# NetSphere Protocol Specifications & Standards Reference

NetSphere implements and references standard Internet Engineering Task Force (IETF) and IEEE standards across all layers of the network model:

## Layer 2 - Data Link Protocols
| Protocol | Standard / RFC | Header Size | Key Fields |
|----------|---------------|-------------|------------|
| **Ethernet II** | IEEE 802.3 | 14 bytes | Dst MAC (6B), Src MAC (6B), EtherType (2B) |
| **ARP / RARP** | RFC 826 / RFC 903 | 28 bytes | Hardware Type, Proto Type, Hardware/Proto Size, Opcode, Sender MAC/IP, Target MAC/IP |
| **802.1Q VLAN** | IEEE 802.1Q | 4 bytes | TPID (0x8100), PCP (3b), DEI (1b), VID (12b), Next EtherType |
| **802.1ad QinQ**| IEEE 802.1ad | 8 bytes | Outer Service VLAN (0x88A8), Inner Customer VLAN (0x8100) |
| **STP** | IEEE 802.1D | 35 bytes | Protocol ID, Version, BPDU Type, Flags, Root ID, Path Cost, Bridge ID, Port ID, Timers |
| **LLDP** | IEEE 802.1AB | Variable | Chassis ID TLV, Port ID TLV, TTL TLV, Port Description TLV, End of LLDPDU |

## Layer 3 - Network Protocols
| Protocol | Standard / RFC | Header Size | Key Fields |
|----------|---------------|-------------|------------|
| **IPv4** | RFC 791 | 20-60 bytes | Version (4b), IHL (4b), TOS (8b), Length (16b), ID (16b), Flags (3b), Frag Offset (13b), TTL (8b), Proto (8b), Checksum (16b), Src/Dst IP |
| **IPv6** | RFC 8200 | 40 bytes | Version (4b), Traffic Class (8b), Flow Label (20b), Payload Len (16b), Next Header (8b), Hop Limit (8b), Src/Dst IP (16B each) |
| **ICMPv4** | RFC 792 | 8 bytes | Type (8b), Code (8b), Checksum (16b), ID (16b), Sequence (16b) |
| **ICMPv6** | RFC 4443 | 8 bytes | Type (8b), Code (8b), Checksum (16b), Message Body |
| **IGMPv2** | RFC 2236 | 8 bytes | Type (8b), Max Resp Time (8b), Checksum (16b), Group Address (32b) |
| **IPsec AH** | RFC 4302 | 12+ bytes | Next Header (8b), Payload Len (8b), SPI (32b), Sequence (32b), ICV |
| **IPsec ESP**| RFC 4303 | 8+ bytes | SPI (32b), Sequence (32b), Encrypted Payload, Padding, ICV |
| **GRE** | RFC 2784 | 4-16 bytes | Flags (16b), Protocol Type (16b), Optional Checksum, Key, Sequence |

## Layer 4 - Transport Protocols
| Protocol | Standard / RFC | Header Size | Key Fields |
|----------|---------------|-------------|------------|
| **TCP** | RFC 793 / 7323 | 20-60 bytes | Src Port (16b), Dst Port (16b), Seq (32b), Ack (32b), Data Offset (4b), Flags (9b), Window (16b), Checksum (16b), Urgent Pointer (16b), Options |
| **UDP** | RFC 768 | 8 bytes | Src Port (16b), Dst Port (16b), Length (16b), Checksum (16b) |
| **SCTP** | RFC 4960 | 12+ bytes | Src Port (16b), Dst Port (16b), Verification Tag (32b), Checksum CRC32c (32b), Chunks |

## Layer 7 - Application Protocols
| Protocol | Standard / RFC | Transport | Description |
|----------|---------------|-----------|-------------|
| **DNS** | RFC 1034 / 1035 | UDP/TCP 53 | Distributed domain name resolution and resource record mapping |
| **DHCP** | RFC 2131 | UDP 67/68 | Dynamic host network configuration and IP lease allocation |
| **HTTP/1.1** | RFC 7230 | TCP 80/8080 | Request/Response messaging, chunked transfer, header grammar |
| **HTTP/2** | RFC 7540 | TCP 443 | Binary multiplexed streaming frames (DATA, HEADERS, SETTINGS) |
| **MQTT** | OASIS v3.1.1/5.0 | TCP 1883 | Lightweight IoT telemetry publish/subscribe messaging |
| **CoAP** | RFC 7252 | UDP 5683 | Constrained RESTful resource interaction protocol |
| **SNMP** | RFC 1157 / 3416 | UDP 161/162 | Network management object polling via ASN.1 BER |
| **BGP-4** | RFC 4271 | TCP 179 | Inter-domain path vector routing and autonomous system peering |
| **OSPFv2** | RFC 2328 | IP 89 | Link-state interior gateway routing and SPF path computation |
| **NTPv4** | RFC 5905 | UDP 123 | Sub-millisecond distributed network clock synchronization |
| **WebSocket** | RFC 6455 | TCP 80/443 | Full-duplex persistent bidirectional framing over single socket |
| **Syslog** | RFC 5424 | UDP/TCP 514 | Structured enterprise security audit and event logging |
