"""
PacketBuffer: high-performance byte manipulation, cursor management, and bit packing.
"""
from __future__ import annotations
import struct
from typing import Union, List, Optional


class PacketBuffer:
    """
    Mutable/Immutable network packet byte buffer.
    Provides cursor-based reading and writing of standard protocol primitives.
    """
    def __init__(self, data: Optional[Union[bytes, bytearray, List[int]]] = None):
        if data is None:
            self._buffer = bytearray()
        elif isinstance(data, bytearray):
            self._buffer = data
        elif isinstance(data, bytes):
            self._buffer = bytearray(data)
        elif isinstance(data, list):
            self._buffer = bytearray(data)
        else:
            raise TypeError(f"Invalid data type for PacketBuffer: {type(data)}")
        self._cursor: int = 0

    @classmethod
    def from_hex(cls, hex_str: str) -> PacketBuffer:
        clean = "".join(hex_str.split())
        return cls(bytes.fromhex(clean))

    def to_hex(self, separator: str = " ") -> str:
        return separator.join(f"{b:02x}" for b in self._buffer)

    def dump_hexdump(self, bytes_per_line: int = 16) -> str:
        """Format buffer as classic Wireshark/tcpdump hex and ASCII dump."""
        lines = []
        for i in range(0, len(self._buffer), bytes_per_line):
            chunk = self._buffer[i:i + bytes_per_line]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            padding = "   " * (bytes_per_line - len(chunk))
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}:  {hex_part}{padding}  |{ascii_part}|")
        return "\n".join(lines)

    @property
    def length(self) -> int:
        return len(self._buffer)

    def __len__(self) -> int:
        return len(self._buffer)

    @property
    def cursor(self) -> int:
        return self._cursor

    @cursor.setter
    def cursor(self, position: int):
        if not 0 <= position <= len(self._buffer):
            raise ValueError(f"Cursor out of bounds: {position} (buffer len: {len(self._buffer)})")
        self._cursor = position

    @property
    def remaining(self) -> int:
        return max(0, len(self._buffer) - self._cursor)

    def has_remaining(self, count: int = 1) -> bool:
        return self.remaining >= count

    def reset(self) -> None:
        self._cursor = 0

    def clear(self) -> None:
        self._buffer.clear()
        self._cursor = 0

    def to_bytes(self) -> bytes:
        return bytes(self._buffer)

    def to_bytearray(self) -> bytearray:
        return bytearray(self._buffer)

    # --- Read Operations (Big Endian Network Order) ---

    def read_bytes(self, count: int) -> bytes:
        if self._cursor + count > len(self._buffer):
            raise IndexError(f"Buffer underflow reading {count} bytes at cursor {self._cursor}")
        val = bytes(self._buffer[self._cursor:self._cursor + count])
        self._cursor += count
        return val

    def peek_bytes(self, count: int) -> bytes:
        if self._cursor + count > len(self._buffer):
            raise IndexError(f"Buffer underflow peeking {count} bytes at cursor {self._cursor}")
        return bytes(self._buffer[self._cursor:self._cursor + count])

    def read_uint8(self) -> int:
        if self._cursor >= len(self._buffer):
            raise IndexError("Buffer underflow reading uint8")
        val = self._buffer[self._cursor]
        self._cursor += 1
        return val

    def read_int8(self) -> int:
        u = self.read_uint8()
        return u if u < 128 else u - 256

    def read_uint16_be(self) -> int:
        raw = self.read_bytes(2)
        return struct.unpack("!H", raw)[0]

    def read_uint16_le(self) -> int:
        raw = self.read_bytes(2)
        return struct.unpack("<H", raw)[0]

    def read_int16_be(self) -> int:
        raw = self.read_bytes(2)
        return struct.unpack("!h", raw)[0]

    def read_uint24_be(self) -> int:
        raw = self.read_bytes(3)
        return (raw[0] << 16) | (raw[1] << 8) | raw[2]

    def read_uint32_be(self) -> int:
        raw = self.read_bytes(4)
        return struct.unpack("!I", raw)[0]

    def read_uint32_le(self) -> int:
        raw = self.read_bytes(4)
        return struct.unpack("<I", raw)[0]

    def read_int32_be(self) -> int:
        raw = self.read_bytes(4)
        return struct.unpack("!i", raw)[0]

    def read_uint64_be(self) -> int:
        raw = self.read_bytes(8)
        return struct.unpack("!Q", raw)[0]

    def read_int64_be(self) -> int:
        raw = self.read_bytes(8)
        return struct.unpack("!q", raw)[0]

    def read_varint(self) -> Tuple[int, int]:
        """Read Protobuf / QUIC style variable-length integer (returns val, bytes_read)."""
        result = 0
        shift = 0
        read_count = 0
        while True:
            b = self.read_uint8()
            read_count += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift >= 64:
                raise ValueError("Varint exceeds 64-bit integer")
        return result, read_count

    # --- Write Operations (Big Endian Network Order) ---

    def write_bytes(self, data: Union[bytes, bytearray, List[int]]) -> PacketBuffer:
        self._buffer.extend(data)
        return self

    def write_uint8(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 255:
            raise ValueError(f"Value out of uint8 range: {val}")
        self._buffer.append(val)
        return self

    def write_int8(self, val: int) -> PacketBuffer:
        if not -128 <= val <= 127:
            raise ValueError(f"Value out of int8 range: {val}")
        self._buffer.append(val if val >= 0 else val + 256)
        return self

    def write_uint16_be(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 65535:
            raise ValueError(f"Value out of uint16 range: {val}")
        self._buffer.extend(struct.pack("!H", val))
        return self

    def write_uint16_le(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 65535:
            raise ValueError(f"Value out of uint16 range: {val}")
        self._buffer.extend(struct.pack("<H", val))
        return self

    def write_int16_be(self, val: int) -> PacketBuffer:
        self._buffer.extend(struct.pack("!h", val))
        return self

    def write_uint24_be(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 0xFFFFFF:
            raise ValueError(f"Value out of uint24 range: {val}")
        self._buffer.append((val >> 16) & 0xFF)
        self._buffer.append((val >> 8) & 0xFF)
        self._buffer.append(val & 0xFF)
        return self

    def write_uint32_be(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 0xFFFFFFFF:
            raise ValueError(f"Value out of uint32 range: {val}")
        self._buffer.extend(struct.pack("!I", val))
        return self

    def write_uint32_le(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 0xFFFFFFFF:
            raise ValueError(f"Value out of uint32 range: {val}")
        self._buffer.extend(struct.pack("<I", val))
        return self

    def write_int32_be(self, val: int) -> PacketBuffer:
        self._buffer.extend(struct.pack("!i", val))
        return self

    def write_uint64_be(self, val: int) -> PacketBuffer:
        if not 0 <= val <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"Value out of uint64 range: {val}")
        self._buffer.extend(struct.pack("!Q", val))
        return self

    def write_int64_be(self, val: int) -> PacketBuffer:
        self._buffer.extend(struct.pack("!q", val))
        return self

    def write_varint(self, val: int) -> PacketBuffer:
        """Write integer encoded as variable-length protobuf style integer."""
        if val < 0:
            raise ValueError(f"Varint must be non-negative, got {val}")
        while True:
            byte = val & 0x7F
            val >>= 7
            if val > 0:
                self._buffer.append(byte | 0x80)
            else:
                self._buffer.append(byte)
                break
        return self

    def insert_at(self, index: int, data: Union[bytes, bytearray]) -> None:
        """Insert raw bytes at specific index."""
        self._buffer[index:index] = data

    def overwrite_at(self, index: int, data: Union[bytes, bytearray]) -> None:
        """Overwrite bytes starting at specific index."""
        end = index + len(data)
        if end > len(self._buffer):
            raise IndexError("Overwrite exceeds buffer length")
        self._buffer[index:end] = data

    def slice(self, start: int, length: Optional[int] = None) -> PacketBuffer:
        """Return a new PacketBuffer containing a subslice."""
        end = len(self._buffer) if length is None else start + length
        return PacketBuffer(self._buffer[start:end])
