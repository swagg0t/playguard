"""Disjoint-set union, used to cluster accounts that share infrastructure.

Union by size with path compression, so each operation is effectively constant
time. On ~10k events this keeps clustering under a millisecond, which matters
because linking has to run on every batch, not nightly.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Hashable, List


class UnionFind:
    def __init__(self) -> None:
        self._parent: Dict[Hashable, Hashable] = {}
        self._size: Dict[Hashable, int] = {}

    def add(self, item: Hashable) -> None:
        if item not in self._parent:
            self._parent[item] = item
            self._size[item] = 1

    def find(self, item: Hashable) -> Hashable:
        self.add(item)
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:      # path compression
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: Hashable, b: Hashable) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self._size[ra] < self._size[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        self._size[ra] += self._size[rb]

    def components(self) -> Dict[Hashable, List[Hashable]]:
        groups: Dict[Hashable, List[Hashable]] = defaultdict(list)
        for item in self._parent:
            groups[self.find(item)].append(item)
        return dict(groups)
