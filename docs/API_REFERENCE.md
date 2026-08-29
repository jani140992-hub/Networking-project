# NetSphere REST & WebSocket API Reference

The embedded NetSphere operations server exposes REST API endpoints and a WebSocket streaming channel for network monitoring, telemetry, and automated diagnostics.

## Base URL
```
http://<host>:<port>/api
```
Default: `http://127.0.0.1:8080/api`

---

## REST Endpoints

### 1. System Operational Status
- **Method:** `GET`
- **Path:** `/api/status`
- **Response:** `200 OK`
```json
{
  "status": "operational",
  "version": "1.0.0",
  "active_nodes": 3,
  "active_links": 2
}
```

### 2. Network Topology Model
- **Method:** `GET`
- **Path:** `/api/topology`
- **Response:** `200 OK`
```json
{
  "name": "EnterpriseCore",
  "nodes": [
    {
      "id": "r1",
      "type": "router",
      "label": "Core-Router-1",
      "x": 300,
      "y": 200,
      "interfaces": [
        {"name": "eth0", "mac": "00:50:56:c0:00:01", "ip": "10.0.0.1"},
        {"name": "eth1", "mac": "00:50:56:c0:00:02", "ip": "10.1.0.1"}
      ]
    }
  ],
  "links": [
    {
      "id": "l1",
      "source": "r1",
      "target": "sw1",
      "sourcePort": "eth0",
      "targetPort": "g0/1",
      "bandwidth": 1000.0,
      "latency": 1.0,
      "active": true
    }
  ]
}
```

### 3. Port Scanner Execution
- **Method:** `POST`
- **Path:** `/api/scan`
- **Payload:**
```json
{
  "target": "127.0.0.1",
  "ports": [21, 22, 23, 25, 80, 443, 8080]
}
```
- **Response:** `200 OK`
```json
{
  "target": "127.0.0.1",
  "scanned_ports": 7,
  "results": [
    {
      "port": 80,
      "status": "open",
      "service": "http",
      "rtt_ms": 1.25,
      "banner": "Apache/2.4.51"
    },
    {
      "port": 23,
      "status": "closed",
      "service": "telnet",
      "rtt_ms": 0.52,
      "banner": ""
    }
  ]
}
```

### 4. Ping Diagnostic Probe
- **Method:** `POST`
- **Path:** `/api/ping`
- **Payload:**
```json
{
  "target": "127.0.0.1",
  "count": 4
}
```
- **Response:** `200 OK`
```json
{
  "target": "127.0.0.1",
  "transmitted": 4,
  "received": 4,
  "packet_loss_pct": 0.0,
  "min_ms": 0.85,
  "avg_ms": 1.15,
  "max_ms": 1.45,
  "jitter_ms": 0.12
}
```

### 5. Live Telemetry Metrics Snapshot
- **Method:** `GET`
- **Path:** `/api/telemetry/metrics`
- **Response:** `200 OK`
```json
{
  "pps": 1420.5,
  "mbps": 11.36,
  "drops_per_sec": 0.0,
  "latency_p50_ms": 1.2,
  "latency_p95_ms": 3.8,
  "latency_p99_ms": 8.4
}
```

---

## WebSocket Event Stream (RFC 6455)
- **URL:** `ws://<host>:8081`
- **Events Emitted:**
  - `packet.flow`: Emitted when packets transit between simulated nodes.
  - `telemetry.tick`: 1-second interval rolling telemetry counters.
  - `anomaly.alert`: Real-time notification when threats (SYN flood, ARP poison) are detected.
