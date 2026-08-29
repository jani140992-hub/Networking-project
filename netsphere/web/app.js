// NetSphere Master Application Controller
document.addEventListener('DOMContentLoaded', () => {
  // 1. Tab Switching
  const navBtns = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.view-panel');

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      navBtns.forEach(b => b.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const targetView = document.getElementById(`view-${btn.dataset.tab}`);
      if (targetView) targetView.classList.add('active');
    });
  });

  // 2. Initialize Subsystems
  const topo = new TopologyCanvas('topo-canvas');
  const inspector = new PacketInspector('packet-tree', 'hex-dump');
  const c1 = new TelemetryChart('chart-throughput', 'Throughput (Mbps)', '#38bdf8');
  const c2 = new TelemetryChart('chart-latency', 'Latency (ms)', '#22c55e');

  // 3. Topology: Add Node Button
  const btnAddNode = document.getElementById('btn-add-node');
  if (btnAddNode) {
    btnAddNode.addEventListener('click', () => {
      const nodeTypes = ['host', 'server', 'firewall'];
      const chosenType = nodeTypes[Math.floor(Math.random() * nodeTypes.length)];
      const nodeCount = topo.nodes.length + 1;
      const label = `${chosenType.toUpperCase()}-${nodeCount}`;
      const newNode = topo.addNode(label, chosenType);
      topo.emitPacket('sw1', newNode.id);
    });
  }

  // 4. Topology: Simulate Packet Button
  const btnSendPacket = document.getElementById('btn-send-packet');
  if (btnSendPacket) {
    btnSendPacket.addEventListener('click', () => {
      topo.emitPacket('gw1', 'sw1');
      setTimeout(() => topo.emitPacket('sw1', 'srv1'), 500);
      setTimeout(() => topo.emitPacket('srv1', 'sw1'), 1200);
      setTimeout(() => topo.emitPacket('sw1', 'cli1'), 1700);
    });
  }

  // 5. Diagnostics: Port Scanner
  const btnRunScan = document.getElementById('btn-run-scan');
  if (btnRunScan) {
    btnRunScan.addEventListener('click', async () => {
      const targetInput = document.getElementById('scan-target').value || '127.0.0.1';
      const tbody = document.querySelector('#scan-results-table tbody');
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#38bdf8;">Scanning ports...</td></tr>';
      try {
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: targetInput, ports: [21, 22, 23, 25, 53, 80, 443, 3306, 8080] })
        });
        const data = await resp.json();
        tbody.innerHTML = '';
        if (data.results && data.results.length > 0) {
          data.results.forEach(r => {
            const row = document.createElement('tr');
            const isOpen = r.status === 'open';
            row.innerHTML = `
              <td><strong>${r.port}</strong></td>
              <td style="color:${isOpen ? '#22c55e' : '#94a3b8'}; font-weight:${isOpen ? '600' : 'normal'}">${r.status.toUpperCase()}</td>
              <td>${r.service}</td>
              <td>${r.rtt_ms} ms</td>
            `;
            tbody.appendChild(row);
          });
        } else {
          tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No open ports found.</td></tr>';
        }
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#ef4444;">Scan failed (check server connection).</td></tr>';
      }
    });
  }

  // 6. Diagnostics: Ping Probe
  const btnRunPing = document.getElementById('btn-run-ping');
  const pingBox = document.getElementById('ping-stats-box');
  if (btnRunPing && pingBox) {
    btnRunPing.addEventListener('click', async () => {
      const targetInput = document.getElementById('ping-target').value || '127.0.0.1';
      pingBox.innerHTML = '<div style="color:#38bdf8; text-align:center;">Sending ping probes...</div>';
      try {
        const resp = await fetch('/api/ping', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: targetInput, count: 4 })
        });
        const d = await resp.json();
        pingBox.innerHTML = `
          <div class="stat-row"><span class="stat-label">Target:</span><span class="stat-val">${d.target}</span></div>
          <div class="stat-row"><span class="stat-label">Transmitted / Received:</span><span class="stat-val">${d.transmitted} / ${d.received}</span></div>
          <div class="stat-row"><span class="stat-label">Packet Loss:</span><span class="stat-val" style="color:${d.packet_loss_pct > 0 ? '#ef4444' : '#22c55e'}">${d.packet_loss_pct}%</span></div>
          <div class="stat-row"><span class="stat-label">Min / Avg / Max RTT:</span><span class="stat-val">${d.min_ms} / ${d.avg_ms} / ${d.max_ms} ms</span></div>
          <div class="stat-row"><span class="stat-label">Interarrival Jitter:</span><span class="stat-val">${d.jitter_ms} ms</span></div>
        `;
      } catch (e) {
        pingBox.innerHTML = '<div style="color:#ef4444; text-align:center;">Ping probe failed.</div>';
      }
    });
  }

  // 7. Catalog Search
  const catalogInput = document.getElementById('catalog-search');
  const catalogResults = document.getElementById('catalog-results');

  async function loadCatalog(query = '') {
    if (!catalogResults) return;
    try {
      const resp = await fetch(`/api/catalog/search?q=${encodeURIComponent(query)}`);
      const data = await resp.json();
      catalogResults.innerHTML = '';
      if (data.items && data.items.length > 0) {
        data.items.forEach(item => {
          const card = document.createElement('div');
          card.className = 'catalog-card';
          card.innerHTML = `
            <div class="catalog-info">
              <h4>${item.title}</h4>
              <p>${item.detail}</p>
            </div>
            <span class="catalog-badge">${item.rfc || item.category}</span>
          `;
          catalogResults.appendChild(card);
        });
      } else {
        catalogResults.innerHTML = '<div style="color:#94a3b8; text-align:center; padding:20px;">No matching ports or standards found.</div>';
      }
    } catch (e) {
      catalogResults.innerHTML = '<div style="color:#ef4444; text-align:center;">Unable to load catalog.</div>';
    }
  }

  if (catalogInput) {
    let debounceTimer;
    catalogInput.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        loadCatalog(catalogInput.value);
      }, 250);
    });
    // Initial catalog population
    loadCatalog('');
  }

  // 8. Live Telemetry Polling (Header bar)
  const ppsEl = document.getElementById('pps-val');
  const mbpsEl = document.getElementById('mbps-val');
  const latEl = document.getElementById('lat-val');

  async function updateHeaderTelemetry() {
    try {
      const resp = await fetch('/api/telemetry/metrics');
      const data = await resp.json();
      if (ppsEl) ppsEl.textContent = Number(data.pps).toLocaleString();
      if (mbpsEl) mbpsEl.textContent = `${data.mbps} Mbps`;
      if (latEl) latEl.textContent = `${data.latency_p50_ms} ms`;
    } catch (e) {}
  }
  setInterval(updateHeaderTelemetry, 2000);
});
