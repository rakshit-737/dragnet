"""Exact, numpy-vectorised TLSH search for the benchmarks (``pip install -e ".[bench]"``).

Same interface as :class:`dragnet.tlsh.TlshIndex` (``add``/``extend``/``nearest``) and the
same distance (it reuses the reference-checked byte table of :mod:`dragnet.tlsh`), but every
query scans all digests exactly: no recall loss, ~1 ms per 20k digests. The runtime engine
stays stdlib-only; a :class:`~dragnet.graph.KnowledgeGraph` accepts this index in place of
the banded one (``kg.tlsh_index = NumpyTlshIndex(...)``).
"""
from __future__ import annotations

from collections.abc import Iterable

import numpy as np

from .tlsh import BODY_BYTES, _table, parse


class NumpyTlshIndex:
    def __init__(self) -> None:
        self._body: list[bytes] = []
        self._head: list[tuple[int, int, int, int]] = []    # checksum, lvalue, q1, q2
        self.labels: list[str] = []
        self.digests: list[str] = []
        self._frozen: tuple[np.ndarray, np.ndarray] | None = None
        self._tab = np.asarray(_table(), dtype=np.int32)

    def __len__(self) -> int:
        return len(self.labels)

    def add(self, digest: str, label: str) -> bool:
        t = parse(digest)
        if t is None:
            return False
        self._body.append(t.body)
        self._head.append((t.checksum, t.lvalue, t.q1, t.q2))
        self.labels.append(label)
        self.digests.append(t.digest)
        self._frozen = None
        return True

    def extend(self, pairs: Iterable[tuple[str, str]]) -> int:
        return sum(self.add(d, lab) for d, lab in pairs)

    def _arrays(self) -> tuple[np.ndarray, np.ndarray]:
        if self._frozen is None:
            body = np.frombuffer(b"".join(self._body), dtype=np.uint8).reshape(-1, BODY_BYTES) \
                if self._body else np.zeros((0, BODY_BYTES), dtype=np.uint8)
            head = np.asarray(self._head, dtype=np.int32).reshape(-1, 4)
            self._frozen = (body.astype(np.int32), head)
        return self._frozen

    def distances(self, digest: str) -> np.ndarray:
        """Distance from ``digest`` to every indexed digest (int32 array)."""
        t = parse(digest)
        if t is None or not self._body:
            return np.zeros(0, dtype=np.int32)
        body, head = self._arrays()
        q = np.frombuffer(t.body, dtype=np.uint8).astype(np.int32)
        d = self._tab[(q[None, :] << 8) | body].sum(axis=1)
        ld = np.abs(head[:, 1] - t.lvalue)
        ld = np.minimum(ld, 256 - ld)
        d += np.where(ld <= 1, ld, ld * 12)
        for col, qv in ((2, t.q1), (3, t.q2)):
            qd = np.abs(head[:, col] - qv)
            qd = np.minimum(qd, 16 - qd)
            d += np.where(qd <= 1, qd, (qd - 1) * 12)
        d += (head[:, 0] != t.checksum).astype(np.int32)
        return d

    def nearest(self, digest: str, k: int = 1, max_dist: int = 10**9,
                exact: bool | None = None) -> list[tuple[int, str, str]]:
        d = self.distances(digest)
        if not len(d):
            return []
        idx = np.nonzero(d <= max_dist)[0]
        if len(idx) > k:
            idx = idx[np.argpartition(d[idx], k - 1)[:k]] if k < len(idx) else idx
        res = sorted((int(d[i]), self.labels[i], self.digests[i]) for i in idx)
        return res[:k]
