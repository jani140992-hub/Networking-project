"""
Binary and Radix Trie for IP Longest Prefix Match (LPM).
Provides O(K) lookup time where K is 32 for IPv4 and 128 for IPv6.
"""
from __future__ import annotations
from typing import Optional, Any, List, Tuple
from netsphere.core.types import IPv4Address, CIDRNetwork


class TrieNode:
    """Node in binary routing prefix trie."""
    def __init__(self, bit: int = -1):
        self.bit = bit
        self.children: List[Optional[TrieNode]] = [None, None]
        self.is_prefix_end = False
        self.prefix_str: str = ""
        self.value: Any = None


class LPMTrie:
    """
    Longest Prefix Match (LPM) Trie implementation for IP routing tables.
    """
    def __init__(self):
        self.root = TrieNode()
        self._entry_count = 0

    @property
    def count(self) -> int:
        return self._entry_count

    def insert(self, cidr: str, value: Any) -> None:
        """
        Insert a CIDR route prefix into the trie (e.g. '192.168.1.0/24', next_hop_data).
        """
        network = CIDRNetwork(cidr)
        addr_int = network.network_address.to_int()
        prefix_len = network.prefix_len

        curr = self.root
        for bit_idx in range(prefix_len):
            bit = (addr_int >> (31 - bit_idx)) & 1
            if curr.children[bit] is None:
                curr.children[bit] = TrieNode(bit)
            curr = curr.children[bit]

        if not curr.is_prefix_end:
            self._entry_count += 1
        curr.is_prefix_end = True
        curr.prefix_str = str(network)
        curr.value = value

    def lookup(self, ip: str) -> Optional[Tuple[str, Any]]:
        """
        Perform Longest Prefix Match for a given destination IP.
        Returns (best_matching_prefix, value) or None if no route found.
        """
        addr_int = IPv4Address(ip).to_int()
        curr = self.root
        best_match: Optional[Tuple[str, Any]] = None

        if curr.is_prefix_end:
            best_match = (curr.prefix_str, curr.value)

        for bit_idx in range(32):
            bit = (addr_int >> (31 - bit_idx)) & 1
            if curr.children[bit] is None:
                break
            curr = curr.children[bit]
            if curr.is_prefix_end:
                best_match = (curr.prefix_str, curr.value)

        return best_match

    def delete(self, cidr: str) -> bool:
        """Remove a prefix from the trie."""
        network = CIDRNetwork(cidr)
        addr_int = network.network_address.to_int()
        prefix_len = network.prefix_len

        path: List[Tuple[TrieNode, int]] = []
        curr = self.root

        for bit_idx in range(prefix_len):
            bit = (addr_int >> (31 - bit_idx)) & 1
            if curr.children[bit] is None:
                return False
            path.append((curr, bit))
            curr = curr.children[bit]

        if not curr.is_prefix_end:
            return False

        curr.is_prefix_end = False
        curr.value = None
        self._entry_count -= 1

        # Prune dead branches
        for parent, bit in reversed(path):
            child = parent.children[bit]
            if child.is_prefix_end or any(child.children):
                break
            parent.children[bit] = None

        return True

    def dump_all_routes(self) -> List[Tuple[str, Any]]:
        """Traverse and collect all registered route prefixes."""
        routes = []

        def _dfs(node: TrieNode):
            if node.is_prefix_end:
                routes.append((node.prefix_str, node.value))
            for ch in node.children:
                if ch is not None:
                    _dfs(ch)

        _dfs(self.root)
        return routes
