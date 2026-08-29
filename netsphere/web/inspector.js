// Wireshark-Style Hierarchical Packet Inspector and Synchronized Hex Dump
class PacketInspector {
  constructor(treeId, hexId) {
    this.treeEl = document.getElementById(treeId);
    this.hexEl = document.getElementById(hexId);
    this.loadSampleFrame();
  }

  loadSampleFrame() {
    const sampleLayers = [
      {
        id: 'layer-frame',
        title: 'Frame 1: 74 bytes on wire (592 bits)',
        range: [0, 74],
        items: [
          'Encapsulation Type: Ethernet II (1)',
          'Arrival Time: 2026-08-29 09:42:00.123456 UTC',
          'Frame Number: 1',
          'Frame Length: 74 bytes (592 bits)',
          'Protocols in frame: eth:ethertype:ip:tcp'
        ]
      },
      {
        id: 'layer-eth',
        title: 'Ethernet II, Src: 00:50:56:c0:00:08, Dst: 00:0c:29:4f:8e:35',
        range: [0, 14],
        items: [
          'Destination: 00:0c:29:4f:8e:35 (VMware, Inc.)',
          'Source: 00:50:56:c0:00:08 (VMware, Inc.)',
          'Type: IPv4 (0x0800)'
        ]
      },
      {
        id: 'layer-ip',
        title: 'Internet Protocol Version 4, Src: 192.168.1.50, Dst: 10.0.0.1',
        range: [14, 34],
        items: [
          '0100 .... = Version: 4',
          '.... 0101 = Header Length: 20 bytes (5)',
          'Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)',
          'Total Length: 60',
          'Identification: 0x1a2b (6699)',
          'Flags: 0x4000, Don\'t fragment',
          'Time to Live: 64',
          'Protocol: TCP (6)',
          'Header Checksum: 0x2a5b [validation disabled]',
          'Source Address: 192.168.1.50',
          'Destination Address: 10.0.0.1'
        ]
      },
      {
        id: 'layer-tcp',
        title: 'Transmission Control Protocol, Src Port: 54321, Dst Port: 443, Seq: 0, Len: 0',
        range: [34, 74],
        items: [
          'Source Port: 54321',
          'Destination Port: 443 (HTTPS)',
          'Sequence Number: 0 (relative sequence number)',
          'Acknowledgment Number: 0',
          '1010 .... = Header Length: 40 bytes (10)',
          'Flags: 0x002 (SYN)',
          'Window: 65535',
          'Checksum: 0x4f12 [verified]',
          'Urgent Pointer: 0',
          'Options: (20 bytes), MSS=1460, SACK permitted, Timestamps'
        ]
      }
    ];

    let html = '';
    sampleLayers.forEach((layer, idx) => {
      html += `
        <div class="tree-layer-group" data-layer-idx="${idx}">
          <div class="tree-node layer" style="cursor:pointer; display:flex; align-items:center; gap:6px;">
            <span class="toggle-icon">▼</span>
            <span>${layer.title}</span>
          </div>
          <div class="layer-body" style="padding-left:20px; margin-bottom:8px;">
            ${layer.items.map(item => `<div class="tree-node item" style="padding:2px 6px; border-radius:3px;">${item}</div>`).join('')}
          </div>
        </div>
      `;
    });
    this.treeEl.innerHTML = html;

    // Attach click listeners to toggle layers and highlight hex
    this.treeEl.querySelectorAll('.tree-node.layer').forEach(header => {
      header.addEventListener('click', (e) => {
        const body = header.nextElementSibling;
        const icon = header.querySelector('.toggle-icon');
        const isCollapsed = body.style.display === 'none';
        body.style.display = isCollapsed ? 'block' : 'none';
        icon.textContent = isCollapsed ? '▼' : '▶';
      });
    });

    this.renderHex();
  }

  renderHex() {
    this.hexEl.textContent =
      "0000   00 0c 29 4f 8e 35 00 50  56 c0 00 08 08 00 45 00   ..)O.5.PV.....E.\\n" +
      "0010   00 3c 1a 2b 40 00 40 06  2a 5b c0 a8 01 32 0a 00   .<.+@.@.*[...2..\\n" +
      "0020   00 01 d4 31 01 bb 00 00  00 00 00 00 00 00 a0 02   ...1............\\n" +
      "0030   ff ff 4f 12 00 00 02 04  05 b4 01 03 03 08 01 01   ..O.............\\n" +
      "0040   04 02 00 00                                        ....";
  }
}
