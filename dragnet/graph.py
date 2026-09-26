"""Evidence-to-actor linkage graph (in-memory, dependency-free)."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .models import Campaign, Signal, SignalKind


class KnowledgeGraph:
    """Bipartite graph: signal-key <-> campaign, campaign -> actor."""

    def __init__(self, campaigns: list[Campaign]):
        self.campaigns = {c.id: c for c in campaigns}
        self.index: dict[tuple[str, str], set[str]] = defaultdict(set)
        for c in campaigns:
            for s in c.signals:
                self.index[s.key].add(c.id)

    @classmethod
    def load(cls, path: str | Path) -> "KnowledgeGraph":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        camps = [
            Campaign(c["id"], c["name"], c["actor"],
                     [Signal(SignalKind(s["kind"]), s["value"]) for s in c["signals"]])
            for c in data["campaigns"]
        ]
        return cls(camps)

    @property
    def actors(self) -> list[str]:
        return sorted({c.actor for c in self.campaigns.values()})

    def actors_for(self, sig: Signal) -> set[str]:
        return {self.campaigns[cid].actor for cid in self.index.get(sig.key, ())}

    def link(self, signals: list[Signal]) -> dict[str, list[Signal]]:
        """actor -> list of case signals that link to it."""
        out: dict[str, list[Signal]] = defaultdict(list)
        for s in signals:
            for a in self.actors_for(s):
                out[a].append(s)
        return dict(out)

    def edges(self, signals: list[Signal]) -> list[tuple[str, str, str]]:
        """(evidence_id, signal_label, campaign_id) edges: the evidence-to-actor path."""
        res = []
        for s in signals:
            for cid in sorted(self.index.get(s.key, ())):
                res.append((s.source, s.label, cid))
        return res
