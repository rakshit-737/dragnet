"""ACH attribution engine + rule-based false-flag reasoner.

Every hypothesis set includes FALSE_FLAG and UNKNOWN by construction.

Per-actor support is a noisy-OR over
  * point signals (IOCs, imphash, code reuse, families, tools, forgeable artifacts),
    each weighted by ``kind weight x specificity`` (1 / #actors the signal links to), and
  * one aggregate TTP term: ``w[ttp_profile] x IDF-cosine(case TTPs, actor profile)``.
Contradiction is the noisy-OR of the same effective weights over signals that link
to *other* actors. score = support x (1 - c x contradiction).

The false-flag reasoner is deliberately rule-based: every indicator is a sentence an
analyst can check. See docs/adr/0003-false-flag-rules.md.
"""
from __future__ import annotations

from dataclasses import dataclass

from .custody import CustodyLog, canonical_hash
from .graph import KnowledgeGraph, ttp_expand
from .models import (
    DEFAULT_WEIGHTS,
    FORGEABLE_KINDS,
    HARD_KINDS,
    Assessment,
    Confidence,
    HypothesisScore,
    Signal,
    SignalKind,
)

FALSE_FLAG = "FALSE_FLAG"
UNKNOWN = "UNKNOWN"
META = (FALSE_FLAG, UNKNOWN)


@dataclass(frozen=True)
class EngineConfig:
    """Switches used by the ablation benchmarks. Defaults = the full engine."""
    specificity: bool = True          # down-weight signals shared by many actors
    ttp_similarity: bool = True       # aggregate TTPs via IDF-cosine instead of per-TTP noisy-OR
    false_flag: bool = True           # run the false-flag reasoner
    contradiction_factor: float = 0.6
    anchor_family_specificity: float = 0.5   # family used by <=2 actors counts as an anchor
    discriminating_forgeable: float = 0.2    # forgeable signal linking to <=5 actors
    divergence_min_sim: float = 0.3          # R4 needs a clearly-matching tradecraft profile
    posterior_gamma: float = 1.0             # p_i ~ score_i ** gamma (1 = plain normalisation; not fitted)
    matrix_top_k: int = 6


DEFAULT_CONFIG = EngineConfig()


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


class _Ctx:
    """Per-assessment view: effective weights, anchors, links."""

    def __init__(self, signals, kg: KnowledgeGraph, w, cfg: EngineConfig):
        self.kg, self.w, self.cfg = kg, w, cfg
        self.signals = signals
        self.ttps = [s.value for s in signals if s.kind == SignalKind.TTP]
        self.point = [s for s in signals if s.kind != SignalKind.TTP] if cfg.ttp_similarity \
            else list(signals)
        self.links = {a: _dedupe(s) for a, s in kg.link(self.point).items()}
        self.linked_keys = {s.key for sigs in self.links.values() for s in sigs}
        self.sim = kg.ttp_similarity(self.ttps) if cfg.ttp_similarity else {}

    def spec(self, s: Signal) -> float:
        if not self.cfg.specificity:
            return 1.0 if self.kg.actors_for(s) else 0.0
        return self.kg.specificity(s)

    def eff(self, s: Signal) -> float:
        return self.w[s.kind] * self.spec(s)

    def is_anchor(self, s: Signal) -> bool:
        if self.w[s.kind] <= 0:
            return False
        if s.kind in HARD_KINDS:
            return True
        return s.kind == SignalKind.FAMILY and self.spec(s) >= self.cfg.anchor_family_specificity

    def is_discriminating_forgeable(self, s: Signal) -> bool:
        return (s.kind in FORGEABLE_KINDS and self.w[s.kind] > 0
                and self.spec(s) >= self.cfg.discriminating_forgeable)


def _names(xs) -> str:
    """Actor/state names as plain text ('A, B'), not a Python list repr."""
    return ", ".join(sorted(xs))


def false_flag_indicators(ctx: _Ctx, point_support: dict[str, float]) -> tuple[list[str], list[str]]:
    """Return (false-flag indicators, informational notes)."""
    ind: list[str] = []
    notes: list[str] = []
    kg, links = ctx.kg, ctx.links
    anchor_actors = {a for a, sigs in links.items() if any(ctx.is_anchor(s) for s in sigs)}
    forg_actors = {a for a, sigs in links.items()
                   if any(ctx.is_discriminating_forgeable(s) for s in sigs)}

    # R1: an actor supported only by forgeable artifacts
    for actor in sorted(forg_actors - anchor_actors):
        kinds = sorted({s.kind.value for s in links[actor] if s.kind in FORGEABLE_KINDS})
        ind.append(f"{actor}: supported only by forgeable/soft signals ({', '.join(kinds)}) "
                   f"with no hard infra/code overlap")
    # R2: forgeable artifacts and hard evidence point to disjoint actor sets
    if forg_actors and anchor_actors and forg_actors.isdisjoint(anchor_actors):
        ind.append(f"forgeable artifacts point to {_names(forg_actors)} "
                   f"while hard evidence points to {_names(anchor_actors)}")
    # R3: specific hard evidence spans several actors
    specific = {a for a in anchor_actors
                if any(ctx.is_anchor(s) and ctx.spec(s) >= ctx.cfg.anchor_family_specificity
                       for s in links[a])}
    if len(specific) >= 2:
        countries = {kg.country(a) for a in specific}
        if None in countries or len(countries) > 1:
            ind.append(f"hard evidence overlaps with multiple actors: {_names(specific)}"
                       + (f" (sponsor states: {_names(c for c in countries if c)})"
                          if any(countries) else ""))
        else:
            notes.append(f"hard evidence shared by overlapping clusters of one sponsor state "
                         f"({countries.pop()}): {_names(specific)} - not treated as a false flag")
    # R4: tooling/infrastructure and tradecraft disagree (tool theft / infra hijack)
    if ctx.sim and point_support:
        a_ttp = max(ctx.sim, key=lambda a: (ctx.sim[a], a))
        anchored = {a: v for a, v in point_support.items() if a in anchor_actors}
        if anchored:
            b_hard = max(anchored, key=lambda a: (anchored[a], a))
            ca, cb = kg.country(a_ttp), kg.country(b_hard)
            s_a, s_b = ctx.sim[a_ttp], ctx.sim.get(b_hard, 0.0)
            if (a_ttp != b_hard and anchored[b_hard] >= 0.3
                    and s_a >= ctx.cfg.divergence_min_sim and s_b < 0.5 * s_a
                    and (ca is None or cb is None or ca != cb)):
                ind.append(f"tooling/infrastructure points to {b_hard} while tradecraft "
                           f"(TTP profile) best matches {a_ttp} - possible tool theft, "
                           f"infrastructure hijack or shared supplier")
    return ind, notes


def assess(case_id: str, signals: list[Signal], kg: KnowledgeGraph,
           weights: dict[SignalKind, float] | None = None,
           custody: CustodyLog | None = None,
           config: EngineConfig = DEFAULT_CONFIG) -> Assessment:
    """Score every actor hypothesis for one case and grade the result.

    :param case_id: identifier echoed into the report.
    :param signals: typed signals from :func:`dragnet.ingest.build_case`.
    :param kg: knowledge graph to match against.
    :param weights: per-kind weight overrides (merged over the defaults).
    :param custody: optional custody log attached to the report.
    :param config: thresholds for the confidence ladder.
    :returns: an :class:`Assessment` with the ACH matrix, flags, grade and guidance.
    """
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)
    cfg = config
    signals = _dedupe(signals)
    ctx = _Ctx(signals, kg, w, cfg)

    eff = {s.key: ctx.eff(s) for s in ctx.point}
    linked = [s for s in ctx.point if s.key in ctx.linked_keys]
    scores: list[HypothesisScore] = []
    point_support: dict[str, float] = {}
    for actor in kg.actors:
        matched = ctx.links.get(actor, [])
        sim = ctx.sim.get(actor, 0.0)
        if not matched and not sim:
            con = noisy_or(eff[s.key] for s in linked)
            scores.append(HypothesisScore(actor, 0.0, con, 0.0, [], []))
            continue
        mkeys = {s.key for s in matched}
        contra = [s for s in linked if s.key not in mkeys]
        psup = noisy_or(eff[s.key] for s in matched)
        point_support[actor] = psup
        sup = noisy_or([psup, w[SignalKind.TTP_PROFILE] * sim])
        con = noisy_or(eff[s.key] for s in contra)
        scores.append(HypothesisScore(actor, sup, con, sup * (1 - cfg.contradiction_factor * con),
                                      matched, contra, sim))

    flags, notes = false_flag_indicators(ctx, point_support) if cfg.false_flag else ([], [])
    forg_w = noisy_or(eff[s.key] for s in linked if s.kind in FORGEABLE_KINDS)
    ff = min(1.0, 0.3 * len(flags) + 0.3 * forg_w) if flags else 0.05 * forg_w
    scores.append(HypothesisScore(FALSE_FLAG, ff, 0.0, ff))
    best_actor = max((h.score for h in scores if h.hypothesis not in META), default=0.0)
    scores.append(HypothesisScore(UNKNOWN, 1.0 - best_actor, 0.0, 1.0 - best_actor))
    scores.sort(key=lambda h: (-h.score, h.hypothesis))

    actor_scores = [h for h in scores if h.hypothesis not in META]
    top = actor_scores[0] if actor_scores and actor_scores[0].score > 0 else None
    runner_up = actor_scores[1].score if len(actor_scores) > 1 else 0.0
    conf, leading = grade(ctx, top, runner_up, flags, scores[0])
    raise_c, lower_c = _guidance(ctx, top, flags)

    shown = [h.hypothesis for h in actor_scores[:cfg.matrix_top_k] if h.score > 0] + list(META)
    matrix = _matrix(ctx, shown)
    shown_set = set(shown)
    links = [e for e in kg.edges(ctx.point) if kg.campaigns[e[2]].actor in shown_set]

    if custody is not None:
        custody.record("assess", case_id,
                       canonical_hash({h.hypothesis: round(h.score, 6) for h in scores}))
    return Assessment(case_id, leading, conf, scores, matrix, flags, raise_c, lower_c,
                      list(custody.entries) if custody else [],
                      {k.value: v for k, v in w.items()}, links, notes,
                      posterior(scores, cfg.posterior_gamma))


def _matrix(ctx: _Ctx, shown: list[str]) -> dict[str, dict[str, str]]:
    matrix: dict[str, dict[str, str]] = {}
    for s in ctx.signals:
        row = {}
        if s.kind == SignalKind.TTP and ctx.cfg.ttp_similarity:
            tids = ttp_expand([s.value])
            users = {a for a in shown if a not in META
                     and tids & ctx.kg.ttp_profiles.get(a, set())}
            for h in shown:
                if h == FALSE_FLAG:
                    row[h] = "N"
                elif h == UNKNOWN:
                    row[h] = "N" if users else "C"
                else:
                    row[h] = "C" if h in users else "N"
            matrix[s.label] = row
            continue
        owners = ctx.kg.actors_for(s)
        for h in shown:
            if h == FALSE_FLAG:
                row[h] = "C" if (s.kind in FORGEABLE_KINDS and owners) else "N"
            elif h == UNKNOWN:
                row[h] = "N" if owners else "C"
            elif not owners:
                row[h] = "N"
            else:
                row[h] = "C" if h in owners else "I"
        matrix[s.label] = row
    return matrix


def posterior(scores, gamma: float = 1.0) -> dict[str, float]:
    """Normalise hypothesis scores into a distribution: p_i ~ score_i ** gamma.

    gamma = 1 is plain normalisation (used for every published result); gamma > 1 sharpens.
    Accepts HypothesisScore objects or (hypothesis, score) pairs."""
    pairs = [(h.hypothesis, h.score) if isinstance(h, HypothesisScore) else h for h in scores]
    powered = [(k, max(0.0, v) ** gamma) for k, v in pairs if v > 0]
    tot = sum(v for _, v in powered)
    if tot <= 0:
        return {UNKNOWN: 1.0}
    return {k: v / tot for k, v in powered}


def grade(ctx: _Ctx, top, runner_up, flags, leading_h) -> tuple[Confidence, str | None]:
    """Confidence ladder; deliberately conservative (ICD-203 style)."""
    if top is None or top.score < 0.3:
        return Confidence.INSUFFICIENT, None
    if flags and leading_h.hypothesis == FALSE_FLAG:
        return Confidence.INSUFFICIENT, None
    anchors = [s for s in top.matched if ctx.is_anchor(s)]
    anchor_kinds = {s.kind for s in anchors}
    margin = top.score - runner_up
    if not anchor_kinds:
        # tradecraft-only (TTP profile / tools): at most LOW, and only with a clear margin
        if top.ttp_similarity > 0 and margin >= 0.1 and not flags:
            return Confidence.LOW, top.hypothesis
        return Confidence.INSUFFICIENT, None
    if top.score >= 0.85 and _independent_anchors(anchors) >= 2 and margin >= 0.3 and not flags:
        return Confidence.HIGH, top.hypothesis
    if top.score >= 0.6 and margin >= 0.2 and not flags:
        return Confidence.MEDIUM, top.hypothesis
    return Confidence.LOW, top.hypothesis


# Kinds that describe the same binary: an imphash and a TLSH digest of one sample are one
# piece of code evidence, not two independent anchors.
_KIND_FAMILY = {SignalKind.IMPHASH: "binary", SignalKind.TLSH: "binary", SignalKind.FILE_HASH: "binary",
                SignalKind.IP: "infra", SignalKind.DOMAIN: "infra"}


def _independent_anchors(anchors: list[Signal]) -> int:
    """Number of independent anchors: distinct kind families, counted only once per evidence
    item (``Signal.source``) when sources are recorded."""
    fams = {_KIND_FAMILY.get(s.kind, s.kind.value) for s in anchors}
    sources = {s.source for s in anchors if s.source}
    if sources and len(sources) < 2 and len(anchors) == sum(1 for s in anchors if s.source):
        return 1
    return len(fams)


def _guidance(ctx: _Ctx, top, flags):
    raise_c = ["Independent infrastructure overlap (C2 IP/domain) with a known campaign",
               "Code-reuse match in non-trivial, non-public functions",
               "Corroboration from an independent reporting source"]
    lower_c = ["Shared infrastructure turns out to be public/shared hosting (CDN, VPS pool)",
               "Shared code is shown to be publicly leaked or open-source",
               "Hard evidence linking to a different actor"]
    if top is not None and not any(ctx.is_anchor(s) for s in top.matched):
        raise_c.insert(0, f"Any hard (infra/code/exclusive-family) signal corroborating {top.hypothesis}")
    if flags:
        lower_c.insert(0, "Confirmation that forgeable artifacts (Rich header, strings) were planted")
    return raise_c, lower_c
