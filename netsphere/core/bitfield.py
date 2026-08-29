"""
Bitfield packing and unpacking utilities for protocol headers.
"""
from typing import Dict, Any, List, Tuple


class BitMask:
    """Computes and stores integer bitmasks."""
    @staticmethod
    def mask(width: int) -> int:
        """Generate a bitmask of given bit width: width 4 -> 0b1111 (0xF)."""
        if width <= 0:
            return 0
        return (1 << width) - 1

    @staticmethod
    def get_bits(value: int, offset: int, width: int) -> int:
        """Extract 'width' bits from 'value' at bit position 'offset' (from LSB)."""
        return (value >> offset) & BitMask.mask(width)

    @staticmethod
    def set_bits(target: int, value: int, offset: int, width: int) -> int:
        """Set 'width' bits in 'target' at 'offset' to 'value'."""
        clean_val = value & BitMask.mask(width)
        mask = BitMask.mask(width) << offset
        return (target & ~mask) | (clean_val << offset)


class BitField:
    """Represents a bitfield descriptor within a composite protocol integer."""
    def __init__(self, name: str, width: int, offset: int, description: str = ""):
        self.name = name
        self.width = width
        self.offset = offset
        self.description = description

    def extract(self, integer_val: int) -> int:
        return BitMask.get_bits(integer_val, self.offset, self.width)

    def pack(self, target_int: int, value: int) -> int:
        return BitMask.set_bits(target_int, value, self.offset, self.width)


def extract_bits(value: int, offset: int, width: int) -> int:
    return BitMask.get_bits(value, offset, width)


def pack_bits(target: int, value: int, offset: int, width: int) -> int:
    return BitMask.set_bits(target, value, offset, width)


class CompositeBitfield:
    """
    Helper for multi-field bit structures (e.g. IPv4 Version + IHL, TCP Data Offset + Flags).
    """
    def __init__(self, total_bits: int, fields: List[Tuple[str, int]]):
        """
        fields: list of (field_name, bit_width) ordered from MSB to LSB.
        """
        self.total_bits = total_bits
        self.fields: Dict[str, BitField] = {}
        current_offset = total_bits
        for name, width in fields:
            current_offset -= width
            self.fields[name] = BitField(name, width, current_offset)
        if current_offset != 0:
            raise ValueError(f"Total bit width mismatch: expected {total_bits}, remaining {current_offset}")

    def decode(self, raw_integer: int) -> Dict[str, int]:
        result = {}
        for name, bf in self.fields.items():
            result[name] = bf.extract(raw_integer)
        return result

    def encode(self, values: Dict[str, int]) -> int:
        packed = 0
        for name, bf in self.fields.items():
            val = values.get(name, 0)
            packed = bf.pack(packed, val)
        return packed
