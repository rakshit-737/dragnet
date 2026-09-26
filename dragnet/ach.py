"""ACH attribution engine + rule-based false-flag reasoner.

Every hypothesis set includes FALSE_FLAG and UNKNOWN by construction.
Scoring is noisy-OR over per-signal weights so independent signals combine
(multi-signal boost) while no single weak signal dominates.
"""
from __future__ import annotations

from .custody import CustodyLog, canonical_hash
from .graph import KnowledgeGraph
from .models import (DEFAULT_WEIGHTS, FORGEABLE_KINDS, HARD_KINDS, Assessment,
                     Confidence, HypothesisScore, Signal, SignalKind)

FALSE_FLAG = "FALSE_FLAG"
UNKNOWN = "UNKNOWN"
META = (FALSE_FLAG, UNKNOWN)


def noisy_or(ws) -> float:
    p = 1.0
    for w in ws:
        p *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - p


def _dedupe(signals: list[Signal]) -> list[Signal]:
    seen, out = set(), []
    for s in signals:
        if s.key not in seen:
            seen.add(s.key)
            out.append(s)
    return out


def false_flag_indicators(links: dict[str, list[Signal]]) -> list[str]:
    ind: list[str] = []
    for actor, sigs in sorted(links.items()):
        kinds = {s.kind for s in sigs}
        forg, hard = kinds & FORGEABLE_KINDS, kinds & HARD_KINDS
        if forg and not hard:
            ind.append(f"{actor}: supported only by forgeable/soft signals "
                       f"({', '.join(sorted(k.value for k in forg))}) with no hard infra/code overlap")
    hard_actors = {a for a, sigs in links.items() if any(s.kind in HARD_KINDS for s in sigs)}
    forg_actors = {a for a, sigs in links.items() if any(s.kind in FORGEABLE_KINDS for s in sigs)}
    if forg_actors and hard_actors and forg_actors.isdisjoint(hard_actors):
        ind.append(f"forgeable artifacts point to {sorted(forg_actors)} "
                   f"while hard evidence points to {sorted(hard_actors)}")
    if len(hard_actors) >= 2:
        ind.append(f"hard evidence overlaps with multiple actors: {sorted(hard_actors)}")
    return ind


def assess(case_id: str, signals: list[Signal], kg: KnowledgeGraph,
           weights: dict[SignalKind, float] | None = None,
           custody: CustodyLog | None = None) -> Assessment:
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)
    signals = _dedupe(signals)
    links = {a: _dedupe(s) for a, s in kg.link(signals).items()}
    linked_keys = {s.key for sigs in links.values() for s in sigs}

    scores: list[HypothesisScore] = []
    for actor in kg.actors:
        matched = links.get(actor, [])
        mkeys = {s.key for s in matched}
        # disconfirming evidence: signals that link to another actor but not this one
        contra = [s for s in signals if s.key in linked_keys and s.key not in mkeys]
        sup = noisy_or(w[s.kind] for s in matched)
        con = noisy_or(w[s.kind] for s in contra)
        scores.append(HypothesisScore(actor, sup, con, sup * (1 - 0.6 * con), matched, contra))

    flags = false_flag_indicators(links)
    forg_w = noisy_or(w[s.kind] for s in signals
                      if s.kind in FORGEABLE_KINDS and s.key in linked_keys)
    ff = min(1.0, 0.3 * len(flags) + 0.3 * forg_w) if flags else 0.05 * forg_w
    scores.append(HypothesisScore(FALSE_FLAG, ff, 0.0, ff))
    best_actor = max((h.score for h in scores if h.hypothesis not in META), default=0.0)
    scores.append(HypothesisScore(UNKNOWN, 1.0 - best_actor, 0.0, 1.0 - best_actor))
    scores.sort(key=lambda h: (-h.score, h.hypothesis))

    matrix: dict[str, dict[str, str]] = {}
    for s in signals:
        owners = kg.actors_for(s)
        row = {}
        for h in scores:
            if h.hypothesis == FALSE_FLAG:
                row[h.hypothesis] = "C" if (s.kind in FORGEABLE_KINDS and owners) else "N"
            elif h.hypothesis == UNKNOWN:
                row[h.hypothesis] = "N" if owners else "C"
            elif not owners:
                row[h.hypothesis] = "N"
            else:
                row[h.hypothesis] = "C" if h.hypothesis in owners else "I"
        matrix[s.label] = row

    actor_scores = sorted((h for h in scores if h.hypothesis not in META),
                          key=lambda h: -h.score)
    top = actor_scores[0] if actor_scores else None
    runner_up = actor_scores[1].score if len(actor_scores) > 1 else 0.0
    conf, leading = grade(top, runner_up, flags, scores[0])
    raise_c, lower_c = _guidance(top, flags)

    if custody is not None:
        custody.record("assess", case_id,
                       canonical_hash({h.hypothesis: round(h.score, 6) for h in scores}))
    return Assessment(case_id, leading, conf, scores, matrix, flags, raise_c, lower_c,
                      list(custody.entries) if custody else [],
                      {k.value: v for k, v in w.items()}, kg.edges(signals))


def grade(top, runner_up, flags, leading_h) -> tuple[Confidence, str | None]:
    """Confidence ladder; deliberately conservative."""
    if top is None or top.score < 0.3:
        return Confidence.INSUFFICIENT, None
    hard_kinds = {s.kind for s in top.matched} & HARD_KINDS
    margin = top.score - runner_up
    if not hard_kinds or (flags and leading_h.hypothesis == FALSE_FLAG):
        return Confidence.INSUFFICIENT, None
    if top.score >= 0.85 and len(hard_kinds) >= 2 and margin >= 0.3 and not flags:
        return Confidence.HIGH, top.hypothesis
    if top.score >= 0.6 and margin >= 0.2 and not flags:
        return Confidence.MEDIUM, top.hypothesis
    return Confidence.LOW, top.hypothesis


def _guidance(top, flags):
    raise_c = ["Independent infrastructure overlap (C2 IP/domain) with a known campaign",
               "Code-reuse match in non-trivial, non-public functions",
               "Corroboration from an independent reporting source"]
    lower_c = ["Shared infrastructure turns out to be public/shared hosting (CDN, VPS pool)",
               "Shared code is shown to be publicly leaked or open-source",
               "Hard evidence linking to a different actor"]
    if top is not None and not any(s.kind in HARD_KINDS for s in top.matched):
        raise_c.insert(0, f"Any hard (infra/code) signal corroborating {top.hypothesis}")
    if flags:
        lower_c.insert(0, "Confirmation that forgeable artifacts (Rich header, strings) were planted")
    return raise_c, lower_c
