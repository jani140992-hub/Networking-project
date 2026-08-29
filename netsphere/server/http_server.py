"""
Pure Python Multi-Threaded HTTP/1.1 Server with Route Matching and Static Asset Serving.
"""
from __future__ import annotations
import json
import mimetypes
import os
import socket
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple


@dataclass
class HTTPRequest:
    method: str
    path: str
    headers: Dict[str, str]
    body: bytes
    query_params: Dict[str, str]


@dataclass
class HTTPResponse:
    status_code: int = 200
    headers: Optional[Dict[str, str]] = None
    body: bytes = b""

    @classmethod
    def json(cls, data: dict, status_code: int = 200) -> HTTPResponse:
        body = json.dumps(data, indent=2).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Access-Control-Allow-Origin": "*",
        }
        return cls(status_code=status_code, headers=headers, body=body)

    @classmethod
    def html(cls, html_str: str, status_code: int = 200) -> HTTPResponse:
        body = html_str.encode("utf-8")
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Access-Control-Allow-Origin": "*",
        }
        return cls(status_code=status_code, headers=headers, body=body)

    def pack(self) -> bytes:
        reasons = {200: "OK", 201: "Created", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}
        reason = reasons.get(self.status_code, "OK")
        lines = [f"HTTP/1.1 {self.status_code} {reason}"]
        headers = self.headers or {}
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if "Content-Length" not in headers:
            lines.append(f"Content-Length: {len(self.body)}")
        lines.append("Connection: close")
        header_text = "\r\n".join(lines) + "\r\n\r\n"
        return header_text.encode("latin1") + self.body


class HTTPServer:
    """
    Multi-threaded HTTP/1.1 server.
    """
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, static_dir: Optional[str] = None):
        self.host = host
        self.port = port
        self.static_dir = static_dir
        self.routes: Dict[Tuple[str, str], Callable[[HTTPRequest], HTTPResponse]] = {}
        self.running = False
        self._server_socket: Optional[socket.socket] = None

    def add_route(self, method: str, path: str, handler: Callable[[HTTPRequest], HTTPResponse]):
        self.routes[(method.upper(), path)] = handler

    def start(self, daemon: bool = False):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(128)
        self.running = True
        print(f"[+] NetSphere HTTP Server listening on http://{self.host}:{self.port}")

        if daemon:
            t = threading.Thread(target=self._accept_loop, daemon=True)
            t.start()
        else:
            self._accept_loop()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self._server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_client(self, sock: socket.socket):
        try:
            sock.settimeout(5.0)
            data = bytearray()
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)

            if not data:
                sock.close()
                return

            header_part, rest = data.split(b"\r\n\r\n", 1)
            lines = header_part.decode("latin1").splitlines()
            req_line = lines[0].split()
            method, full_path = req_line[0], req_line[1]

            path = full_path.split("?")[0]
            query_params = {}
            if "?" in full_path:
                q_str = full_path.split("?", 1)[1]
                for pair in q_str.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        query_params[k] = v

            headers = {}
            for l in lines[1:]:
                if ":" in l:
                    k, v = l.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            content_len = int(headers.get("content-length", 0))
            body = rest
            while len(body) < content_len:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body.extend(chunk)

            req = HTTPRequest(method=method, path=path, headers=headers, body=bytes(body), query_params=query_params)

            # Match route
            handler = self.routes.get((method.upper(), path))
            if handler:
                response = handler(req)
            elif self.static_dir and self._try_serve_static(path):
                response = self._try_serve_static(path)
            else:
                response = HTTPResponse.json({"error": "Not Found", "path": path}, status_code=404)

            sock.sendall(response.pack())
        except Exception:
            pass
        finally:
            sock.close()

    def _try_serve_static(self, path: str) -> Optional[HTTPResponse]:
        if not self.static_dir:
            return None
        rel_path = path.lstrip("/")
        if not rel_path or rel_path == "/":
            rel_path = "index.html"
        full = os.path.abspath(os.path.join(self.static_dir, rel_path))
        if os.path.exists(full) and os.path.isfile(full):
            mime, _ = mimetypes.guess_type(full)
            with open(full, "rb") as f:
                content = f.read()
            return HTTPResponse(
                status_code=200,
                headers={"Content-Type": mime or "application/octet-stream", "Content-Length": str(len(content))},
                body=content,
            )
        return None

    def stop(self):
        self.running = False
        if self._server_socket:
            self._server_socket.close()
