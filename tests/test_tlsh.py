"""TLSH distance against the trendmicro reference vectors, and banded-index recall."""
import random
from pathlib import Path

import pytest

from dragnet import tlsh as T
from dragnet.graph import KnowledgeGraph
from dragnet.models import Campaign, Signal, SignalKind
from dragnet.paths import data_dir

FIX = Path(__file__).resolve().parent / "fixtures" / "tlsh"


def _digests(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        h, name = line.split("\t")
        out[name.strip()] = h.strip()
    return out


def _check_pairs(digests: dict[str, str], scores: Path) -> int:
    n = 0
    for line in scores.read_text().splitlines():
        a, b, want = line.split("\t")
        if a in digests and b in digests:
            assert T.diff(digests[a], digests[b]) == int(want), (a, b)
            n += 1
    return n


def test_distance_matches_reference_subset():
    assert _check_pairs(_digests(FIX / "digests.tsv"), FIX / "xref_scores.tsv") >= 60


def test_distance_properties():
    d = _digests(FIX / "digests.tsv")
    a, b = list(d.values())[:2]
    assert T.diff(a, a) == 0
    assert T.diff(a, b) == T.diff(b, a) > 0
    assert T.parse("T1ZZ") is None
    with pytest.raises(ValueError):
        T.Tlsh("T1ABC")


def _perturb(rng: random.Random, h: str, dist: int) -> str:
    body = bytearray(T.Tlsh(h).body)
    head = h[2:8]
    while T.diff(h, "T1" + head + body.hex().upper()) < dist:
        i, k = rng.randrange(32), rng.randrange(4)
        c = (body[i] >> 2 * k) & 3
        body[i] = (body[i] & ~(3 << 2 * k)) | (((c + rng.choice((1, -1))) % 4) << 2 * k)
    return "T1" + head + body.hex().upper()


def test_banded_recall_matches_exact_search():
    rng = random.Random(7)
    base = ["T1" + "".join(rng.choice("0123456789ABCDEF") for _ in range(70)) for _ in range(300)]
    idx = T.TlshIndex(exact_below=0)            # force the banded path
    idx.extend((h, f"f{i}") for i, h in enumerate(base))
    for dist in (30, 50):
        hits = 0
        for i in range(100):
            q = _perturb(rng, base[i], dist)
            exact = idx.nearest(q, k=1, max_dist=dist + 30, exact=True)
            banded = idx.nearest(q, k=1, max_dist=dist + 30, exact=False)
            hits += banded == exact
        assert hits >= 95, (dist, hits)


def test_small_index_is_exhaustive():
    rng = random.Random(3)
    h = "T1" + "".join(rng.choice("0123456789ABCDEF") for _ in range(70))
    idx = T.TlshIndex()
    idx.add(h, "fam")
    q = _perturb(rng, h, 120)                   # far beyond what any band would catch
    assert idx.nearest(q, max_dist=200)[0][1] == "fam"


def test_graph_matches_tlsh_by_distance():
    rng = random.Random(5)
    h = "T1" + "".join(rng.choice("0123456789ABCDEF") for _ in range(70))
    kg = KnowledgeGraph([Campaign("C1", "c", "ACTOR", [Signal(SignalKind.TLSH, h)])])
    near, far = _perturb(rng, h, 20), _perturb(rng, h, 200)
    assert kg.actors_for(Signal(SignalKind.TLSH, near)) == {"ACTOR"}
    assert kg.actors_for(Signal(SignalKind.TLSH, far)) == frozenset()


REF = data_dir() / "tlsh-xref-scores.txt"


@pytest.mark.realdata
@pytest.mark.skipif(not REF.exists(), reason="TLSH reference vectors not downloaded")
def test_distance_matches_full_reference():
    assert _check_pairs(_digests(data_dir() / "tlsh-digests.txt"), REF) == 3160


def test_imphash_and_tlsh_of_one_sample_are_not_two_anchors():
    from dragnet.ach import assess
    from dragnet.models import Confidence
    rng = random.Random(9)
    h = "T1" + "".join(rng.choice("0123456789ABCDEF") for _ in range(70))
    kg = KnowledgeGraph([Campaign("C1", "c", "A", [Signal(SignalKind.TLSH, h), Signal(SignalKind.IMPHASH, "i1"),
                                                   Signal(SignalKind.IP, "10.0.0.1")])])
    one_sample = [Signal(SignalKind.TLSH, h, "s1"), Signal(SignalKind.IMPHASH, "i1", "s1")]
    assert assess("x", one_sample, kg).confidence != Confidence.HIGH
    two_items = [*one_sample, Signal(SignalKind.IP, "10.0.0.1", "netflow")]
    assert assess("y", two_items, kg).confidence == Confidence.HIGH
