"""
Pure Python RFC 6455 WebSocket Server for Real-Time Telemetry and Event Streaming.
"""
from __future__ import annotations
import base64
import hashlib
import socket
import threading
from typing import List, Optional, Callable
from netsphere.protocols.l7.websocket import WebSocketFrame, WebSocketOpcode


class WebSocketClient:
    """Represents a connected WebSocket client session."""
    def __init__(self, sock: socket.socket, addr):
        self.sock = sock
        self.addr = addr
        self.is_open = True

    def send_text(self, text: str):
        if not self.is_open:
            return
        frame = WebSocketFrame.text(text, mask=False)
        try:
            self.sock.sendall(frame.pack())
        except Exception:
            self.is_open = False


class WebSocketServer:
    """
    Lightweight RFC 6455 WebSocket broadcasting server.
    """
    WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, host: str = "0.0.0.0", port: int = 8081):
        self.host = host
        self.port = port
        self.clients: List[WebSocketClient] = []
        self._lock = threading.Lock()
        self.running = False
        self._server_sock: Optional[socket.socket] = None

    def start(self, daemon: bool = True):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(64)
        self.running = True
        print(f"[+] NetSphere WebSocket Server listening on ws://{self.host}:{self.port}")

        t = threading.Thread(target=self._accept_loop, daemon=daemon)
        t.start()

    def _accept_loop(self):
        while self.running:
            try:
                sock, addr = self._server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(sock, addr), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_client(self, sock: socket.socket, addr):
        try:
            # Perform RFC 6455 handshake
            data = sock.recv(2048).decode("latin1", errors="replace")
            if "Sec-WebSocket-Key:" not in data:
                sock.close()
                return

            key = ""
            for line in data.splitlines():
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
                    break

            accept_val = base64.b64encode(hashlib.sha1((key + self.WS_GUID).encode("utf-8")).digest()).decode("utf-8")
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_val}\r\n\r\n"
            )
            sock.sendall(response.encode("latin1"))

            client = WebSocketClient(sock, addr)
            with self._lock:
                self.clients.append(client)

            # Keep reading frames
            while client.is_open:
                chunk = sock.recv(4096)
                if not chunk:
                    break
        except Exception:
            pass
        finally:
            sock.close()

    def broadcast_json(self, data: dict):
        import json
        text = json.dumps(data)
        with self._lock:
            active_clients = []
            for c in self.clients:
                if c.is_open:
                    c.send_text(text)
                    active_clients.append(c)
            self.clients = active_clients
