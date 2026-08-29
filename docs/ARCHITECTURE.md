# NetSphere Architecture Specification

## Overview

NetSphere is an enterprise-grade Network Operations, Protocol Engineering, and Telemetry Platform implemented in modular Python 3. It provides full OSI L2–L7 protocol dissection, Software-Defined Networking (SDN) topology simulation, virtual switching, longest-prefix-match (LPM) routing, traffic shaping, TCP congestion control models, multi-vector port scanning, network diagnostics, NetFlow/sFlow telemetry, and an embedded REST/WebSocket NOC operations console.

---

## Subsystem Architecture

```
+-------------------------------------------------------------------------------+
|                             NetSphere Web NOC Dashboard                       |
|        (Canvas Topology Visualizer, Wireshark-Style Dissector, Gauges)        |
+---------------------------------------+---------------------------------------+
                                        | (HTTP / WebSockets RFC 6455)
+---------------------------------------v---------------------------------------+
|                    Embedded Operations Server (HTTP & WS)                     |
|            - Thread-Safe Event Bus (netsphere.core.events / server.bus)        |
|            - REST API Controllers (Topology, Scans, Diagnostics, Metrics)     |
+---------------------------------------+---------------------------------------+
                                        |
       +--------------------------------+-------------------------------+
       |                                |                               |
+------v----------------+     +---------v----------+     +--------------v-------+
|  SDN Simulation Engine|     | Scanner & Telemetry|     | Protocol Dissectors  |
| - Virtual L2 Switch   |     | - TCP SYN/FIN/ACK  |     | - L2: Eth, ARP, VLAN |
| - L3 LPM Trie Router  |     | - NetFlow v5/v9    |     | - L3: IPv4, IPv6, ICMP|
| - NAT / PAT Gateway   |     | - Anomaly Detector |     | - L4: TCP, UDP, SCTP |
| - QoS (TBF, WFQ, RED) |     | - Ping & Traceroute|     | - L7: DNS, DHCP, HTTP|
| - TCP Reno/Cubic/BBR  |     | - OS Fingerprinting|     | - MQTT, SNMP, BGP... |
+-----------------------+     +--------------------+     +----------------------+
                                        |
+---------------------------------------v---------------------------------------+
|                   Enterprise Standards Registries & Catalogs                  |
|   - IANA Ports Directory (1-65535)         - IEEE OUI MAC Vendor DB           |
|   - IANA IP Protocols (0-255)              - SNMP Standard MIB Tree (RFCs)    |
+-------------------------------------------------------------------------------+
```

---

## 1. Core Primitives (`netsphere.core`)
- **`PacketBuffer`**: Cursor-based mutable network packet buffer with big-endian wire serialization, slicing, and Wireshark-style hexadecimal dump output.
- **`BitField` & `BitMask`**: Arithmetic bit packing and unpacking for composite protocol header fields.
- **`Checksum`**: Implementation of RFC 1071 16-bit one's complement checksum, incremental checksum updates (RFC 1624), CRC-16, CRC-32 (IEEE 802.3 Ethernet FCS), Adler-32, and Fletcher-16.
- **`Types`**: Strongly-typed immutable dataclasses for IPv4, IPv6, IEEE 802 MAC addresses, and CIDR subnet blocks.
- **`EventBus`**: Synchronous and asynchronous pub/sub event dispatcher.

---

## 2. Protocol Engineering Stack (`netsphere.protocols`)
- **Layer 2 (Data Link)**:
  - `EthernetHeader`: IEEE 802.3 and Ethernet II framing with EtherType dispatch.
  - `ARPHeader`: RFC 826 ARP request/reply, RARP, and gratuitous ARP detection.
  - `VLANHeader` & `QinQHeader`: IEEE 802.1Q / 802.1ad priority code points and VLAN tagging.
  - `STPHeader`: Spanning Tree Protocol BPDU configuration and topology change notifications.
  - `LLDPHeader`: Link Layer Discovery Protocol TLV parsers.
- **Layer 3 (Network Layer)**:
  - `IPv4Header`: RFC 791 IPv4 header, fragmentation flags (DF/MF), fragment offset, options, and automated checksum.
  - `IPv6Header`: RFC 8200 fixed 40-octet header with flow label, traffic class, and extension headers.
  - `ICMPHeader` & `ICMPv6Header`: Echo Request/Reply, Destination Unreachable, Time Exceeded, and Neighbor Discovery.
  - `IGMPHeader`: IGMPv1/v2/v3 multicast group membership reports.
  - `AHHeader` & `ESPHeader`: IPsec RFC 4302/4303 security headers.
  - `GREHeader`: RFC 2784 multi-protocol tunnel encapsulation.
- **Layer 4 (Transport Layer)**:
  - `TCPHeader`: RFC 793 / RFC 7323 header, window scale, SACK, timestamps, and options.
  - `TCPConnection`: RFC 793 Finite State Machine (CLOSED -> SYN_SENT -> ESTABLISHED -> TIME_WAIT).
  - `RTTTracker`: Van Jacobson / Karels algorithm for smoothed RTT and retransmission timeout (RTO) estimation.
  - `UDPHeader`: RFC 768 connectionless datagram transport with IPv4 pseudo-header checksum.
  - `SCTPHeader`: RFC 4960 multi-homed stream transmission protocol with chunk model.
- **Layer 7 (Application Layer)**:
  - `DNSMessage`: RFC 1035 wire parser and builder, name compression pointers, question/answer/authority RR structures.
  - `DHCPMessage`: RFC 2131 BOOTP/DHCP message format, magic cookie, and option parsing.
  - `HTTP1Request` & `HTTP1Response`: RFC 7230 parser, headers normalization, chunked transfer.
  - `HTTP2Frame`: RFC 7540 9-octet binary framing, stream multiplexing.
  - `MQTTMessage`: OASIS standard MQTT v3.1.1/v5.0 publish/subscribe control packet engine.
  - `CoAPMessage`: RFC 7252 constrained application protocol messages.
  - `SNMPMessage`: RFC 1157 SNMP ASN.1 BER encoding, PDU types, and VarBind lists.
  - `BGPMessage`: RFC 4271 BGP-4 OPEN, UPDATE, KEEPALIVE framing.
  - `OSPFMessage`: RFC 2328 link-state routing protocol headers.
  - `NTPMessage`: RFC 5905 64-bit nanosecond clock synchronization timestamps.
  - `WebSocketFrame`: RFC 6455 framing, masking, and opcode processing.

---

## 3. Simulation & Software-Defined Networking (`netsphere.simulation`)
- **Virtual Switch (`VirtualSwitch`)**: Dynamic MAC address learning table with configurable aging timer (default 300s), unicast forwarding, broadcast/multicast flooding, and VLAN trunk/access isolation.
- **Virtual Router (`VirtualRouter`)**: Longest Prefix Match (LPM) Trie routing table, ARP resolution cache, TTL decrement, and ICMP error generation.
- **LPM Trie (`LPMTrie`)**: Binary tree supporting $O(32)$ IPv4 prefix lookups and dynamic prefix insertion/deletion.
- **NAT / PAT Engine (`NATEngine`)**: Stateful connection tracking table mapping private IP:Port pairs to public IP:AllocatedPort with reverse translation.
- **Graph Routing (`NetworkGraph`)**: Dijkstra's Shortest Path First algorithm, Bellman-Ford distance-vector algorithm, and Floyd-Warshall all-pairs shortest path matrix.
- **QoS Queuing (`qos.py`)**: Token Bucket Filter (TBF), Leaky Bucket policer, Multi-level Priority Queuing (PQ), Weighted Fair Queuing (WFQ), and Random Early Detection (RED) probabilistic drop engine.
- **TCP Congestion Control (`congestion.py`)**: Tahoe, Reno, CUBIC ($W(t) = C(t - K)^3 + W_{max}$), and BBR (Bottleneck Bandwidth and RTT) state machines.

---

## 4. Diagnostics & Security Auditing (`netsphere.scanner`, `netsphere.diagnostics`)
- **Port Scanner (`PortScanner`)**: Thread pool concurrent scanner supporting TCP Connect, SYN, and UDP probing with service resolution.
- **OS Fingerprinting (`OSFingerprinter`)**: Analyzes initial TTL, TCP window sizes, and DF bits to deduce remote OS kernels (Linux, Windows, macOS, Cisco IOS).
- **Ping & Traceroute**: High-precision round-trip time, packet loss, standard deviation ($mdev$), and RFC 3550 interarrival jitter.
- **Security Auditor**: Detects exposed unencrypted protocols (Telnet, FTP, cleartext SMB) and misconfigured network services.

---

## 5. Telemetry & Flow Monitoring (`netsphere.telemetry`)
- **NetFlow v5 (`NetFlowCollector`)**: Collector and parser for 48-byte NetFlow v5 records.
- **sFlow (`SFlowCollector`)**: Packet sampling datagram processor.
- **Time-Series Metrics**: Rolling rate counters for packets-per-second, bits-per-second, and latency percentiles (P50, P95, P99).
- **Anomaly Detection**: Heuristic detection of TCP SYN floods, ARP cache poisoning, port scan sweeps, and amplification attacks.
