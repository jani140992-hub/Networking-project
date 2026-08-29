// Wireshark-Style Hierarchical Packet Inspector and Hex Dump
class PacketInspector {
  constructor(treeId, hexId) {
    this.treeEl = document.getElementById(treeId);
    this.hexEl = document.getElementById(hexId);
    this.loadSampleFrame();
  }

  loadSampleFrame() {
    const sampleLayers = [
      {
        title: 'Frame 1: 74 bytes on wire (592 bits)',
        items: ['Encapsulation: Ethernet II', 'Arrival Time: 2026-08-29 09:42:00 UTC', 'Frame Length: 74 bytes']
      },
      {
        title: 'Ethernet II, Src: 00:50:56:c0:00:08, Dst: 00:0c:29:4f:8e:35',
        items: ['Destination: 00:0c:29:4f:8e:35 (VMware)', 'Source: 00:50:56:c0:00:08', 'Type: IPv4 (0x0800)']
      },
      {
        title: 'Internet Protocol Version 4, Src: 192.168.1.50, Dst: 10.0.0.1',
        items: ['0100 .... = Version: 4', '.... 0101 = Header Length: 20 bytes', 'Total Length: 60', 'TTL: 64', 'Protocol: TCP (6)', 'Header Checksum: 0x2a5b [verified]']
      },
      {
        title: 'Transmission Control Protocol, Src Port: 54321, Dst Port: 443, Seq: 0, Len: 0',
        items: ['Source Port: 54321', 'Destination Port: 443 (HTTPS)', 'Sequence Number: 0 (relative)', 'Flags: 0x002 (SYN)', 'Window: 65535', 'Checksum: 0x4f12']
      }
    ];

    let html = '';
    for (const layer of sampleLayers) {
      html += `<div class="tree-node layer">▶ ${layer.title}</div><div style="padding-left:16px; margin-bottom:8px;">`;
      for (const item of layer.items) {
        html += `<div class="tree-node">${item}</div>`;
      }
      html += '</div>';
    }
    this.treeEl.innerHTML = html;

    this.hexEl.textContent =
      "0000   00 0c 29 4f 8e 35 00 50  56 c0 00 08 08 00 45 00   ..)O.5.PV.....E.\n" +
      "0010   00 3c 1a 2b 40 00 40 06  2a 5b c0 a8 01 32 0a 00   .<.+@.@.*[...2..\n" +
      "0020   00 01 d4 31 01 bb 00 00  00 00 00 00 00 00 a0 02   ...1............\n" +
      "0030   ff ff 4f 12 00 00 02 04  05 b4 01 03 03 08 01 01   ..O.............\n" +
      "0040   04 02 00 00                                        ....";
  }
}
