"""
Hypertext Transfer Protocol Version 1.1 (HTTP/1.1 - RFC 7230).
"""
from __future__ import annotations
from typing import Dict, Optional, Tuple


class HTTP1Request:
    """HTTP/1.1 Request model."""
    def __init__(
        self,
        method: str = "GET",
        path: str = "/",
        version: str = "HTTP/1.1",
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
    ):
        self.method = method.upper()
        self.path = path
        self.version = version
        self.headers = headers or {"Host": "localhost", "User-Agent": "NetSphere/1.0"}
        self.body = body

    def pack(self) -> bytes:
        lines = [f"{self.method} {self.path} {self.version}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        if self.body and "Content-Length" not in self.headers:
            lines.append(f"Content-Length: {len(self.body)}")
        header_text = "\r\n".join(lines) + "\r\n\r\n"
        return header_text.encode("latin1") + self.body

    @classmethod
    def unpack(cls, data: bytes) -> HTTP1Request:
        header_sep = b"\r\n\r\n"
        if header_sep not in data:
            header_sep = b"\n\n"
            if header_sep not in data:
                raise ValueError("Malformed HTTP/1.1 Request (missing header delimiter)")

        raw_headers, body = data.split(header_sep, 1)
        lines = raw_headers.decode("latin1", errors="replace").splitlines()
        if not lines:
            raise ValueError("Empty HTTP/1.1 Request")

        request_line = lines[0].split()
        if len(request_line) < 3:
            raise ValueError(f"Malformed HTTP request line: {lines[0]}")
        method, path, version = request_line[0], request_line[1], request_line[2]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return cls(method=method, path=path, version=version, headers=headers, body=body)


class HTTP1Response:
    """HTTP/1.1 Response model."""
    def __init__(
        self,
        status_code: int = 200,
        reason: str = "OK",
        version: str = "HTTP/1.1",
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
    ):
        self.status_code = status_code
        self.reason = reason
        self.version = version
        self.headers = headers or {"Server": "NetSphere-Server/1.0", "Content-Type": "text/plain"}
        self.body = body

    def pack(self) -> bytes:
        lines = [f"{self.version} {self.status_code} {self.reason}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        if "Content-Length" not in self.headers:
            lines.append(f"Content-Length: {len(self.body)}")
        header_text = "\r\n".join(lines) + "\r\n\r\n"
        return header_text.encode("latin1") + self.body

    @classmethod
    def unpack(cls, data: bytes) -> HTTP1Response:
        header_sep = b"\r\n\r\n"
        if header_sep not in data:
            header_sep = b"\n\n"
            if header_sep not in data:
                raise ValueError("Malformed HTTP/1.1 Response")

        raw_headers, body = data.split(header_sep, 1)
        lines = raw_headers.decode("latin1", errors="replace").splitlines()
        status_line = lines[0].split(maxsplit=2)
        version = status_line[0]
        status_code = int(status_line[1])
        reason = status_line[2] if len(status_line) > 2 else "OK"

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return cls(status_code=status_code, reason=reason, version=version, headers=headers, body=body)
