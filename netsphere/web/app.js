// Master Application Controller
document.addEventListener('DOMContentLoaded', () => {
  // Tab Switching
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

  // Init Subsystems
  const topo = new TopologyCanvas('topo-canvas');
  const inspector = new PacketInspector('packet-tree', 'hex-dump');
  const c1 = new TelemetryChart('chart-throughput', 'Throughput (Mbps)', '#38bdf8');
  const c2 = new TelemetryChart('chart-latency', 'Latency (ms)', '#22c55e');

  // Simulate Packet Button
  document.getElementById('btn-send-packet').addEventListener('click', () => {
    topo.emitPacket('gw1', 'sw1');
    setTimeout(() => topo.emitPacket('sw1', 'srv1'), 600);
  });

  // Diagnostics Scan
  document.getElementById('btn-run-scan').addEventListener('click', async () => {
    const tbody = document.querySelector('#scan-results-table tbody');
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Scanning ports...</td></tr>';
    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: document.getElementById('scan-target').value, ports: [21,22,25,80,443,3306,8080] })
      });
      const data = await resp.json();
      tbody.innerHTML = '';
      data.results.forEach(r => {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${r.port}</td><td style="color:${r.status === 'open' ? '#22c55e' : '#94a3b8'}">${r.status}</td><td>${r.service}</td><td>${r.rtt_ms} ms</td>`;
        tbody.appendChild(row);
      });
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="4">Scan failed or offline</td></tr>';
    }
  });
});
