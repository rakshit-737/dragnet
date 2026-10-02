"""TLSH fuzzy-hash distance and a banded nearest-neighbour index (stdlib only).

MalwareBazaar publishes a TLSH digest (Oliver, Cheng & Chen, "TLSH - A Locality Sensitive
Hash", CTC 2013) for most samples. DRAGNET never sees a binary; it only compares these
published digests. The distance below re-implements the reference ``TlshImpl::totalDiff``
with length difference ("len" mode) and is checked against the reference test vectors of
trendmicro/tlsh (``Testing/exp/example_data.128.1.len.xref.scores_EXP``): a committed subset is
in ``tests/fixtures/tlsh`` (``tests/test_tlsh.py``); the full 3,160-pair file is checked by the
``realdata`` test when the datasets are downloaded.

Digest layout (version "T1", 128 buckets, 1-byte checksum, 70 hex characters):
``T1`` | checksum (1 byte, nibble-swapped) | L-value (1 byte, nibble-swapped) |
Q-ratios (1 byte: q1 = high nibble after swap... both are compared the same way) | 32-byte body.

Index: exact search over hundreds of thousands of digests is too slow in pure Python, so
:class:`TlshIndex` buckets digests by *bands* of the body (the body is 128 two-bit bucket
codes; near-identical files share most of them). A query is compared exactly only against
digests that share at least one band. Small indexes (``<= exact_below`` digests) are always
searched exhaustively. Recall of the banded search against brute force is measured, not assumed:
``tests/test_tlsh.py`` (synthetic pairs) and section E3 of ``scripts/run_benchmarks.py`` (real
MalwareBazaar digests).
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

BODY_BYTES = 32


def _swap(b: int) -> int:
    return ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)


def _mod_diff(x: int, y: int, r: int) -> int:
    d = abs(x - y)
    return min(d, r - d)


def _bitpair_table() -> list[int]:
    t = []
    for a in range(256):
        for b in range(256):
            s = 0
            for k in range(4):
                d = abs(((a >> 2 * k) & 3) - ((b >> 2 * k) & 3))
                s += 6 if d == 3 else d
            t.append(s)
    return t


_DIFF: list[int] = []            # 65536 entries: body-byte pair -> distance contribution (lazy)


def _table() -> list[int]:
    if not _DIFF:
        _DIFF.extend(_bitpair_table())
    return _DIFF


class Tlsh:
    __slots__ = ("body", "checksum", "digest", "lvalue", "q1", "q2")

    def __init__(self, digest: str):
        h = digest.strip().upper()
        h = h.removeprefix("T1")
        if len(h) != 70:
            raise ValueError(f"unsupported TLSH digest length: {digest!r}")
        raw = bytes.fromhex(h)
        self.checksum = _swap(raw[0])
        self.lvalue = _swap(raw[1])
        qr = _swap(raw[2])
        self.q1, self.q2 = qr & 0x0F, qr >> 4
        self.body = raw[3:]
        self.digest = "T1" + h

    def diff(self, other: Tlsh, len_diff: bool = True) -> int:
        return diff_parts(self, other, len_diff)


def diff_parts(a: Tlsh, b: Tlsh, len_diff: bool = True) -> int:
    d = 0
    if len_diff:
        ld = _mod_diff(a.lvalue, b.lvalue, 256)
        d += ld if ld <= 1 else ld * 12
    for x, y in ((a.q1, b.q1), (a.q2, b.q2)):
        q = _mod_diff(x, y, 16)
        d += q if q <= 1 else (q - 1) * 12
    if a.checksum != b.checksum:
        d += 1
    t = _table()
    ab, bb = a.body, b.body
    for i in range(BODY_BYTES):
        d += t[(ab[i] << 8) | bb[i]]
    return d


def diff(h1: str, h2: str, len_diff: bool = True) -> int:
    """TLSH distance between two digests (0 = identical; < ~50 usually the same family)."""
    return diff_parts(Tlsh(h1), Tlsh(h2), len_diff)


def parse(digest: str) -> Tlsh | None:
    try:
        return Tlsh(digest)
    except ValueError:
        return None


class TlshIndex:
    """Banded candidate index over TLSH digests with exact re-ranking.

    ``bands`` splits the 32-byte body into equal slices; two digests become candidates if any
    slice is byte-identical. More bands = shorter slices = higher recall, more candidates. The
    default (32 one-byte bands) was chosen after 16 two-byte bands missed ~20% of true pairs at
    distance 50 on real digests. Indexes with at most ``exact_below`` digests skip the bands.
    """

    def __init__(self, bands: int = 32, exact_below: int = 5000):
        if BODY_BYTES % bands:
            raise ValueError("bands must divide 32")
        self.bands = bands
        self.exact_below = exact_below
        self.width = BODY_BYTES // bands
        self.items: list[tuple[Tlsh, str]] = []           # (digest, label)
        self.buckets: list[dict[bytes, list[int]]] = [defaultdict(list) for _ in range(bands)]

    def __len__(self) -> int:
        return len(self.items)

    def add(self, digest: str, label: str) -> bool:
        t = parse(digest)
        if t is None:
            return False
        i = len(self.items)
        self.items.append((t, label))
        w = self.width
        for b in range(self.bands):
            self.buckets[b][t.body[b * w:(b + 1) * w]].append(i)
        return True

    def extend(self, pairs: Iterable[tuple[str, str]]) -> int:
        return sum(self.add(d, lab) for d, lab in pairs)

    def candidates(self, t: Tlsh, max_bucket: int = 5000) -> set[int]:
        """Band-sharing candidates; very large buckets (constant regions, e.g. all-zero
        slices of tiny files) are skipped, which is what keeps queries sub-linear."""
        out: set[int] = set()
        w = self.width
        for b in range(self.bands):
            hit = self.buckets[b].get(t.body[b * w:(b + 1) * w])
            if hit and len(hit) <= max_bucket:
                out.update(hit)
        return out

    def nearest(self, digest: str, k: int = 1, max_dist: int = 10**9,
                exact: bool | None = None) -> list[tuple[int, str, str]]:
        """k nearest (distance, label, digest) within ``max_dist``. ``exact`` = brute force
        (default: only when the index holds at most ``exact_below`` digests)."""
        t = parse(digest)
        if t is None:
            return []
        if exact is None:
            exact = len(self.items) <= self.exact_below
        idx = range(len(self.items)) if exact else self.candidates(t)
        res = []
        for i in idx:
            o, lab = self.items[i]
            d = diff_parts(t, o)
            if d <= max_dist:
                res.append((d, lab, o.digest))
        res.sort()
        return res[:k]
