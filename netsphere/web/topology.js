// HTML5 Canvas Network Topology Visualizer and Packet Flow Animator
class TopologyCanvas {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.nodes = [
      { id: 'gw1', label: 'Edge Router', x: 450, y: 100, type: 'router', color: '#f59e0b' },
      { id: 'sw1', label: 'Core Switch', x: 450, y: 240, type: 'switch', color: '#38bdf8' },
      { id: 'srv1', label: 'App Server', x: 250, y: 380, type: 'server', color: '#22c55e' },
      { id: 'srv2', label: 'DB Cluster', x: 450, y: 380, type: 'server', color: '#22c55e' },
      { id: 'cli1', label: 'Admin Host', x: 650, y: 380, type: 'host', color: '#a855f7' }
    ];
    this.links = [
      { from: 'gw1', to: 'sw1' },
      { from: 'sw1', to: 'srv1' },
      { from: 'sw1', to: 'srv2' },
      { from: 'sw1', to: 'cli1' }
    ];
    this.particles = [];
    this.initEvents();
    this.animate();
  }

  initEvents() {
    window.addEventListener('resize', () => this.resize());
    this.resize();
  }

  resize() {
    this.canvas.width = this.canvas.parentElement.clientWidth;
    this.canvas.height = 500;
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
      }
    }

    // Draw Particles
    this.particles = this.particles.filter(p => {
      p.progress += p.speed;
      const cx = p.x + (p.tx - p.x) * p.progress;
      const cy = p.y + (p.ty - p.y) * p.progress;
      this.ctx.fillStyle = '#38bdf8';
      this.ctx.shadowBlur = 8;
      this.ctx.shadowColor = '#38bdf8';
      this.ctx.beginPath();
      this.ctx.arc(cx, cy, 5, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
      return p.progress < 1.0;
    });

    // Draw Nodes
    for (const n of this.nodes) {
      this.ctx.fillStyle = n.color;
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, 22, 0, Math.PI * 2);
      this.ctx.fill();

      this.ctx.fillStyle = '#f8fafc';
      this.ctx.font = '12px monospace';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(n.label, n.x, n.y + 36);
    }

    requestAnimationFrame(() => this.animate());
  }
}
