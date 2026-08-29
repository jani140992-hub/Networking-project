// Real-time Canvas Telemetry Line Charts
class TelemetryChart {
  constructor(canvasId, label, color) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.label = label;
    this.color = color;
    this.dataPoints = Array(30).fill(10);
    this.init();
  }

  init() {
    setInterval(() => {
      const nextVal = Math.max(5, Math.min(100, this.dataPoints[this.dataPoints.length - 1] + (Math.random() * 10 - 5)));
      this.dataPoints.push(nextVal);
      this.dataPoints.shift();
      this.draw();
    }, 1000);
  }

  draw() {
    const w = this.canvas.width;
    const h = this.canvas.height;
    this.ctx.clearRect(0, 0, w, h);

    // Grid lines
    this.ctx.strokeStyle = '#1e293b';
    this.ctx.lineWidth = 1;
    for (let y = 20; y < h; y += 40) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(w, y);
      this.ctx.stroke();
    }

    // Chart Line
    this.ctx.strokeStyle = this.color;
    this.ctx.lineWidth = 2;
    this.ctx.beginPath();
    const step = w / (this.dataPoints.length - 1);
    this.dataPoints.forEach((val, idx) => {
      const y = h - (val / 100) * (h - 40) - 20;
      if (idx === 0) this.ctx.moveTo(0, y);
      else this.ctx.lineTo(idx * step, y);
    });
    this.ctx.stroke();

    // Label
    this.ctx.fillStyle = '#94a3b8';
    this.ctx.font = '12px monospace';
    this.ctx.fillText(`${this.label}: ${this.dataPoints[this.dataPoints.length - 1].toFixed(1)}`, 10, 20);
  }
}
