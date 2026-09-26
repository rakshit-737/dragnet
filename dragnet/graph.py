"""Evidence-to-actor knowledge graph (in-memory, dependency-free).

Bipartite index: signal-key <-> campaign, campaign -> actor. On top of the raw
index the graph provides the two quantities the ACH engine needs on real data:

* ``specificity(sig)``  - how discriminating a signal is (1 / #actors it links to).
  Mimikatz is used by ~60 ATT&CK groups; a bespoke implant by one. Without this,
  large, well-documented actors win every match simply by having more edges.
* ``ttp_similarity(ttps)`` - IDF-weighted cosine similarity between the case's
  ATT&CK techniques and every actor's technique profile ("TTP embedding"): rare
  techniques count more, and the cosine normalises away profile size.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path

from .models import Campaign, Signal, SignalKind


def ttp_expand(tids) -> set[str]:
    """T1059.001 -> {T1059.001, T1059}: a sub-technique also evidences its parent."""
    out = set()
    for t in tids:
        t = t.strip().upper()
        if t:
            out.add(t)
            out.add(t.split(".")[0])
    return out


class KnowledgeGraph:
    def __init__(self, campaigns: list[Campaign], actor_meta: dict[str, dict] | None = None,
                 meta: dict | None = None):
        self.campaigns = {c.id: c for c in campaigns}
        self.actor_meta = actor_meta or {}
        self.meta = meta or {}
        self.index: dict[tuple[str, str], set[str]] = defaultdict(set)
        for c in campaigns:
            for s in c.signals:
                self.index[s.key].add(c.id)
        self._actors = sorted({c.actor for c in campaigns})
        self._actor_cache: dict[tuple[str, str], frozenset[str]] = {}
        # TTP profiles + IDF
        prof: dict[str, set[str]] = defaultdict(set)
        for c in campaigns:
            prof[c.actor] |= ttp_expand(s.value for s in c.signals if s.kind == SignalKind.TTP)
        self.ttp_profiles = dict(prof)
        df: dict[str, int] = defaultdict(int)
        for ttps in prof.values():
            for t in ttps:
                df[t] += 1
        n = max(1, len(self._actors))
        self.idf = {t: math.log((n + 1) / (d + 1)) + 1.0 for t, d in df.items()}
        self._norm = {a: math.sqrt(sum(self.idf[t] ** 2 for t in ttps)) or 1.0
                      for a, ttps in prof.items()}

    # --- construction --------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> KnowledgeGraph:
        camps = [
            Campaign(c["id"], c["name"], c["actor"],
                     [Signal(SignalKind(s["kind"]), str(s["value"])) for s in c["signals"]])
            for c in data["campaigns"]
        ]
        return cls(camps, data.get("actors", {}), data.get("meta", {}))

    @classmethod
    def load(cls, path: str | Path) -> KnowledgeGraph:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_dict(self) -> dict:
        return {
            "meta": self.meta,
            "actors": self.actor_meta,
            "campaigns": [
                {"id": c.id, "name": c.name, "actor": c.actor,
                 "signals": [{"kind": s.kind.value, "value": s.value} for s in c.signals]}
                for c in self.campaigns.values()
            ],
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), separators=(",", ":")), encoding="utf-8")

    # --- queries -------------------------------------------------------------
    @property
    def actors(self) -> list[str]:
        return self._actors

    def actors_for(self, sig: Signal) -> frozenset[str]:
        k = sig.key
        hit = self._actor_cache.get(k)
        if hit is None:
            hit = frozenset(self.campaigns[cid].actor for cid in self.index.get(k, ()))
            self._actor_cache[k] = hit
        return hit

    def specificity(self, sig: Signal) -> float:
        n = len(self.actors_for(sig))
        return 1.0 / n if n else 0.0

    def country(self, actor: str) -> str | None:
        return (self.actor_meta.get(actor) or {}).get("country")

    def link(self, signals: list[Signal]) -> dict[str, list[Signal]]:
        """actor -> list of case signals that link to it."""
        out: dict[str, list[Signal]] = defaultdict(list)
        for s in signals:
            for a in self.actors_for(s):
                out[a].append(s)
        return dict(out)

    def ttp_similarity(self, ttps) -> dict[str, float]:
        """IDF-weighted cosine between the case TTP set and every actor profile."""
        q = {t for t in ttp_expand(ttps) if t in self.idf}
        if not q:
            return {}
        qn = math.sqrt(sum(self.idf[t] ** 2 for t in q))
        out = {}
        for a, prof in self.ttp_profiles.items():
            inter = q & prof
            if inter:
                out[a] = sum(self.idf[t] ** 2 for t in inter) / (qn * self._norm[a])
        return out

    def edges(self, signals: list[Signal]) -> list[tuple[str, str, str]]:
        """(evidence_id, signal_label, campaign_id) edges: the evidence-to-actor path."""
        res = []
        for s in signals:
            for cid in sorted(self.index.get(s.key, ())):
                res.append((s.source, s.label, cid))
        return res
