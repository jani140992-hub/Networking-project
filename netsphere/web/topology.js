// HTML5 Canvas Network Topology Visualizer and Packet Flow Animator
class TopologyCanvas {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.nodes = [
      { id: 'gw1', label: 'Edge Router', x: 450, y: 80, type: 'router', color: '#f59e0b', ip: '10.0.0.1' },
      { id: 'sw1', label: 'Core Switch', x: 450, y: 220, type: 'switch', color: '#38bdf8', ip: '10.0.0.2' },
      { id: 'srv1', label: 'App Server', x: 220, y: 380, type: 'server', color: '#22c55e', ip: '10.0.1.10' },
      { id: 'srv2', label: 'DB Cluster', x: 450, y: 380, type: 'server', color: '#22c55e', ip: '10.0.1.20' },
      { id: 'cli1', label: 'Admin Host', x: 680, y: 380, type: 'host', color: '#a855f7', ip: '10.0.2.100' }
    ];
    this.links = [
      { from: 'gw1', to: 'sw1' },
      { from: 'sw1', to: 'srv1' },
      { from: 'sw1', to: 'srv2' },
      { from: 'sw1', to: 'cli1' }
    ];
    this.particles = [];
    this.draggedNode = null;
    this.dragOffset = { x: 0, y: 0 };
    this.selectedNode = null;

    this.initEvents();
    this.animate();
  }

  initEvents() {
    window.addEventListener('resize', () => this.resize());
    this.resize();

    // Mouse drag-and-drop on nodes
    this.canvas.addEventListener('mousedown', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      for (let i = this.nodes.length - 1; i >= 0; i--) {
        const n = this.nodes[i];
        const dist = Math.hypot(n.x - mx, n.y - my);
        if (dist <= 26) {
          this.draggedNode = n;
          this.selectedNode = n;
          this.dragOffset.x = mx - n.x;
          this.dragOffset.y = my - n.y;
          this.showNodeDetails(n);
          break;
        }
      }
    });

    this.canvas.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      if (this.draggedNode) {
        this.draggedNode.x = Math.max(30, Math.min(this.canvas.width - 30, mx - this.dragOffset.x));
        this.draggedNode.y = Math.max(30, Math.min(this.canvas.height - 40, my - this.dragOffset.y));
      } else {
        const hovered = this.nodes.some(n => Math.hypot(n.x - mx, n.y - my) <= 26);
        this.canvas.style.cursor = hovered ? 'grab' : 'default';
      }
    });

    window.addEventListener('mouseup', () => {
      if (this.draggedNode) {
        this.draggedNode = null;
        this.canvas.style.cursor = 'default';
      }
    });
  }

  showNodeDetails(node) {
    console.log(`[Topology] Selected Node: ${node.label} (${node.ip})`);
  }

  resize() {
    this.canvas.width = this.canvas.parentElement.clientWidth;
    this.canvas.height = 500;
  }

  addNode(label, type) {
    const id = `node_${this.nodes.length + 1}`;
    const colors = { router: '#f59e0b', switch: '#38bdf8', server: '#22c55e', host: '#a855f7' };
    const color = colors[type] || '#38bdf8';
    const x = 150 + (this.nodes.length * 70) % (this.canvas.width - 250);
    const y = 200 + (this.nodes.length * 40) % 200;
    const newNode = { id, label: label || `Node-${this.nodes.length + 1}`, x, y, type: type || 'host', color, ip: `10.0.${this.nodes.length}.1` };
    this.nodes.push(newNode);

    // Link to Core Switch
    this.links.push({ from: 'sw1', to: id });
    return newNode;
  }

  emitPacket(fromId, toId) {
    const fromNode = this.nodes.find(n => n.id === fromId);
    const toNode = this.nodes.find(n => n.id === toId);
    if (fromNode && toNode) {
      this.particles.push({
        x: fromNode.x, y: fromNode.y,
        tx: toNode.x, ty: toNode.y,
        progress: 0,
        speed: 0.02
      });
    }
  }

  animate() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    // Draw Links
    this.ctx.lineWidth = 2;
    this.ctx.strokeStyle = '#334155';
    for (const l of this.links) {
      const n1 = this.nodes.find(n => n.id === l.from);
      const n2 = this.nodes.find(n => n.id === l.to);
      if (n1 && n2) {
        this.ctx.beginPath();
        this.ctx.moveTo(n1.x, n1.y);
        this.ctx.lineTo(n2.x, n2.y);
        this.ctx.stroke();

        // Draw small midpoint link badge
        const mx = (n1.x + n2.x) / 2;
        const my = (n1.y + n2.y) / 2;
        this.ctx.fillStyle = '#1e293b';
        this.ctx.fillRect(mx - 12, my - 6, 24, 12);
        this.ctx.fillStyle = '#64748b';
        this.ctx.font = '9px monospace';
        this.ctx.fillText('1Gb', mx - 8, my + 3);
      }
    }

    // Draw Particles
    this.particles = this.particles.filter(p => {
      p.progress += p.speed;
      const cx = p.x + (p.tx - p.x) * p.progress;
      const cy = p.y + (p.ty - p.y) * p.progress;
      this.ctx.fillStyle = '#38bdf8';
      this.ctx.shadowBlur = 10;
      this.ctx.shadowColor = '#38bdf8';
      this.ctx.beginPath();
      this.ctx.arc(cx, cy, 6, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
      return p.progress < 1.0;
    });

    // Draw Nodes
    for (const n of this.nodes) {
      // Glow if selected
      if (this.selectedNode === n) {
        this.ctx.strokeStyle = '#38bdf8';
        this.ctx.lineWidth = 3;
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, 28, 0, Math.PI * 2);
        this.ctx.stroke();
      }

      this.ctx.fillStyle = n.color;
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, 22, 0, Math.PI * 2);
      this.ctx.fill();

      // Icon inside node
      this.ctx.fillStyle = '#0f172a';
      this.ctx.font = '12px sans-serif';
      this.ctx.textAlign = 'center';
      const icon = n.type === 'router' ? '⚡' : n.type === 'switch' ? '🔀' : n.type === 'server' ? '🖥️' : '💻';
      this.ctx.fillText(icon, n.x, n.y + 4);

      // Label below
      this.ctx.fillStyle = '#f8fafc';
      this.ctx.font = 'bold 12px monospace';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(n.label, n.x, n.y + 36);

      // IP badge below label
      if (n.ip) {
        this.ctx.fillStyle = '#94a3b8';
        this.ctx.font = '10px monospace';
        this.ctx.fillText(n.ip, n.x, n.y + 48);
      }
    }

    requestAnimationFrame(() => this.animate());
  }
}
