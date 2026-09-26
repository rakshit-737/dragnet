"""Attribution benchmarks on real public data.

Research question (spec): does multi-signal ACH attribution outperform single-signal
(TTP-only or IOC/code-only) matching in accuracy and calibration, especially under
false-flag conditions?

Methods compared on identical evidence and identical knowledge graphs:
  dragnet            full engine (specificity + IDF-cosine TTPs + false-flag reasoner)
  dragnet-no-spec    ablation: every linked signal counts fully
  dragnet-no-ttpsim  ablation: TTPs as individual noisy-OR signals
  dragnet-no-ff      ablation: false-flag reasoner disabled
  ttp-jaccard        baseline: nearest actor by Jaccard over ATT&CK technique sets
  ioc-correlation    baseline: MISP-style shared-indicator count (families/tools/IOCs)
  code-only          baseline: shared family/imphash/code-reuse count only

Ties in a baseline ranking are scored in expectation (random tie-breaking), so no
method benefits from alphabetical luck.
"""
from __future__ import annotations

import math
import random
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable

from .ach import FALSE_FLAG, UNKNOWN, EngineConfig, assess, posterior
from .graph import KnowledgeGraph, ttp_expand
from .models import Campaign, Signal, SignalKind
from .sources.attack import AttackData
from .sources.misp import COUNTRY_LANG, norm

CODE_KINDS = {SignalKind.FAMILY, SignalKind.IMPHASH, SignalKind.CODE_REUSE, SignalKind.FILE_HASH}


# ----------------------------------------------------------------------------- data
@dataclass
class Case:
    case_id: str
    name: str
    signals: list[Signal]
    truth: set[str]                  # acceptable actor names; empty = actor not in KG
    meta: dict = field(default_factory=dict)


@dataclass
class Prediction:
    scores: dict[str, float]         # actor -> score (>0 only)
    probs: dict[str, float]          # hypothesis -> probability (may include UNKNOWN)
    named: str | None                # actor the method commits to (None = abstain)
    grade: str | None = None
    flags: int = 0
    hyp_scores: list[tuple[str, float]] | None = None   # raw scores, for re-calibration


def novel_family_cases(attack: AttackData, min_techniques: int = 5) -> list[Case]:
    """A3: every ATT&CK malware family used by exactly one group -> a case whose evidence
    is only the family's documented techniques (the family itself is withheld, as if it
    were brand new). Tests behaviour-only attribution at scale."""
    out = []
    for sid, gids in sorted(attack.software_attribution().items(),
                            key=lambda kv: attack.software[kv[0]].attack_id):
        sw = attack.software[sid]
        if sw.type != "malware" or len(gids) != 1:
            continue
        tids = sorted(attack.techniques_of(sid))
        if len(tids) < min_techniques:
            continue
        g = attack.groups[next(iter(gids))]
        out.append(Case(sw.attack_id, sw.name, [Signal(SignalKind.TTP, t, sw.attack_id) for t in tids],
                        {g.name}, {"group": g.name, "n_ttp": len(tids)}))
    return out


def campaign_signals(attack: AttackData, cid: str) -> list[Signal]:
    sigs = [Signal(SignalKind.TTP, t, cid) for t in sorted(attack.techniques_of(cid))]
    for sid in sorted(attack.software_of(cid)):
        sw = attack.software[sid]
        kind = SignalKind.FAMILY if sw.type == "malware" else SignalKind.TOOL
        sigs.append(Signal(kind, sw.name, cid))
    return sigs


def attack_campaign_cases(attack_eval: AttackData, attack_kg: AttackData,
                          created_after: str | None = None) -> list[Case]:
    """Every attributed ATT&CK campaign -> a case. Truth is resolved in the KG's
    ATT&CK version by stable STIX id (empty truth = group unknown to that KG)."""
    out = []
    for cid, gid in sorted(attack_eval.attributed.items(),
                           key=lambda kv: attack_eval.campaigns[kv[0]].attack_id):
        c = attack_eval.campaigns[cid]
        if created_after and (c.created or "") <= created_after:
            continue
        sigs = campaign_signals(attack_eval, cid)
        if not sigs:
            continue
        g = attack_kg.groups.get(gid)
        out.append(Case(c.attack_id, c.name, sigs, {g.name} if g else set(),
                        {"group": attack_eval.groups[gid].name, "created": c.created,
                         "n_ttp": sum(s.kind == SignalKind.TTP for s in sigs),
                         "n_software": sum(s.kind != SignalKind.TTP for s in sigs)}))
    return out


# -------------------------------------------------------------------------- methods
def dragnet_method(cfg: EngineConfig = EngineConfig()) -> Callable[[list[Signal], KnowledgeGraph], Prediction]:
    def run(signals, kg):
        a = assess("bench", signals, kg, config=cfg)
        scores = {h.hypothesis: h.score for h in a.hypotheses
                  if h.hypothesis not in (FALSE_FLAG, UNKNOWN) and h.score > 0}
        return Prediction(scores, a.posterior, a.leading, a.confidence.value,
                          len(a.false_flag_indicators),
                          [(h.hypothesis, h.score) for h in a.hypotheses])
    return run


def _normalise(scores: dict[str, float]) -> dict[str, float]:
    tot = sum(scores.values())
    return {k: v / tot for k, v in scores.items()} if tot > 0 else {}


def _top(scores: dict[str, float]) -> str | None:
    return max(scores, key=lambda a: (scores[a], a)) if scores else None


def ttp_jaccard(signals, kg: KnowledgeGraph) -> Prediction:
    q = ttp_expand(s.value for s in signals if s.kind == SignalKind.TTP)
    scores = {}
    for a, prof in kg.ttp_profiles.items():
        inter = len(q & prof)
        if inter:
            scores[a] = inter / len(q | prof)
    return Prediction(scores, _normalise(scores), _top(scores))


def ttp_cosine(signals, kg: KnowledgeGraph) -> Prediction:
    """Stronger TTP baseline: the same IDF-cosine DRAGNET uses, with nothing else."""
    scores = kg.ttp_similarity(s.value for s in signals if s.kind == SignalKind.TTP)
    return Prediction(scores, _normalise(scores), _top(scores))


def _count_baseline(kinds: set[SignalKind] | None):
    def run(signals, kg: KnowledgeGraph) -> Prediction:
        pts = [s for s in signals if s.kind != SignalKind.TTP and (kinds is None or s.kind in kinds)]
        counts = Counter()
        for s in pts:
            for a in kg.actors_for(s):
                counts[a] += 1
        scores = {a: float(c) for a, c in counts.items()}
        return Prediction(scores, _normalise(scores), _top(scores))
    return run


METHODS: dict[str, Callable[[list[Signal], KnowledgeGraph], Prediction]] = {
    "dragnet": dragnet_method(),
    "dragnet-no-spec": dragnet_method(EngineConfig(specificity=False)),
    "dragnet-no-ttpsim": dragnet_method(EngineConfig(ttp_similarity=False)),
    "dragnet-no-ff": dragnet_method(EngineConfig(false_flag=False)),
    "ttp-jaccard": ttp_jaccard,
    "ttp-cosine": ttp_cosine,
    "ioc-correlation": _count_baseline(None),
    "code-only": _count_baseline(CODE_KINDS),
}


# -------------------------------------------------------------------------- metrics
def _rank_credit(scores: dict[str, float], truth: set[str], k: int) -> float:
    """P(truth in top-k) under random tie-breaking; best-placed acceptable actor counts."""
    best = 0.0
    for t in truth:
        if t not in scores:
            continue
        v = scores[t]
        above = sum(1 for x in scores.values() if x > v)
        ties = sum(1 for x in scores.values() if x == v)
        best = max(best, min(1.0, max(0.0, (k - above) / ties)))
    return best


def _rr(scores, truth) -> float:
    best = 0.0
    for t in truth:
        if t not in scores:
            continue
        v = scores[t]
        above = sum(1 for x in scores.values() if x > v)
        ties = sum(1 for x in scores.values() if x == v)
        best = max(best, sum(1.0 / (above + i + 1) for i in range(ties)) / ties)
    return best


def _brier(probs: dict[str, float], truth: set[str]) -> float:
    if truth:
        tgt = max(truth, key=lambda t: probs.get(t, 0.0))
    else:
        tgt = UNKNOWN
    keys = set(probs) | {tgt}
    return sum((probs.get(k, 0.0) - (1.0 if k == tgt else 0.0)) ** 2 for k in keys)


def _top_hyp(probs: dict[str, float]) -> tuple[str | None, float]:
    cand = {k: v for k, v in probs.items() if k != FALSE_FLAG}
    if not cand:
        return None, 0.0
    k = max(cand, key=lambda x: (cand[x], x))
    return k, cand[k]


def ece(pairs: list[tuple[float, bool]], bins: int = 10) -> float:
    if not pairs:
        return float("nan")
    tot = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(p, c) for p, c in pairs if (lo <= p < hi) or (b == bins - 1 and p == 1.0)]
        if sel:
            conf = sum(p for p, _ in sel) / len(sel)
            acc = sum(c for _, c in sel) / len(sel)
            tot += len(sel) / len(pairs) * abs(conf - acc)
    return tot


def reliability(pairs: list[tuple[float, bool]], bins: int = 10) -> list[dict]:
    out = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(p, c) for p, c in pairs if (lo <= p < hi) or (b == bins - 1 and p == 1.0)]
        if sel:
            out.append({"lo": lo, "hi": hi, "n": len(sel),
                        "confidence": sum(p for p, _ in sel) / len(sel),
                        "accuracy": sum(c for _, c in sel) / len(sel)})
    return out


def predict_all(method: str, cases: list[Case], kg: KnowledgeGraph) -> list[Prediction]:
    return [METHODS[method](c.signals, kg) for c in cases]


def evaluate(method: str, cases: list[Case], kg: KnowledgeGraph,
             preds: list[Prediction] | None = None, gamma: float | None = None,
             label: str | None = None) -> dict:
    preds = preds if preds is not None else predict_all(method, cases, kg)
    rows = []
    for c, p in zip(cases, preds):
        if gamma is not None and p.hyp_scores is not None:
            p = Prediction(p.scores, posterior(p.hyp_scores, gamma), p.named, p.grade, p.flags,
                           p.hyp_scores)
        in_kg = bool(c.truth)
        named_ok = p.named in c.truth if p.named else False
        top_h, top_p = _top_hyp(p.probs)
        correct_top = (top_h in c.truth) if in_kg else (top_h in (None, UNKNOWN))
        rows.append({
            "case": c.case_id, "name": c.name, "truth": sorted(c.truth),
            "in_kg": in_kg, "named": p.named, "grade": p.grade, "flags": p.flags,
            "top1": _rank_credit(p.scores, c.truth, 1), "top3": _rank_credit(p.scores, c.truth, 3),
            "top5": _rank_credit(p.scores, c.truth, 5), "rr": _rr(p.scores, c.truth),
            "named_ok": named_ok, "brier": _brier(p.probs, c.truth),
            "top_hyp": top_h, "top_p": top_p, "top_ok": correct_top,
            # binary forecast "the top-ranked actor is the culprit": DRAGNET states its
            # ACH score for that actor; baselines only have their normalised share.
            "p_leader": (p.scores.get(_top(p.scores), 0.0) if p.hyp_scores is not None
                         else _normalise(p.scores).get(_top(p.scores), 0.0)) if p.scores else 0.0,
            "leader_ok": _top(p.scores) in c.truth if p.scores else False,
            "p_truth": max((p.probs.get(t, 0.0) for t in c.truth), default=p.probs.get(UNKNOWN, 0.0)),
            "leader": _top(p.scores),
        })
    return summarise(label or method, rows)


def summarise(method: str, rows: list[dict]) -> dict:
    ink = [r for r in rows if r["in_kg"]]
    ook = [r for r in rows if not r["in_kg"]]
    named = [r for r in ink if r["named"]]
    confident = [r for r in rows if r["grade"] in ("HIGH", "MEDIUM")] if rows and rows[0]["grade"] \
        else [r for r in rows if r["named"]]
    mean = lambda xs: sum(xs) / len(xs) if xs else float("nan")  # noqa: E731
    grades = {}
    if rows and rows[0]["grade"] is not None:
        for g in ("HIGH", "MEDIUM", "LOW", "INSUFFICIENT"):
            sel = [r for r in ink if r["grade"] == g]
            grades[g] = {"n": len(sel), "accuracy": mean([r["named_ok"] for r in sel]) if g != "INSUFFICIENT"
                         else mean([r["top1"] for r in sel])}
    pairs = [(min(1.0, r["p_leader"]), r["leader_ok"]) for r in rows]
    return {
        "method": method, "n": len(rows), "n_in_kg": len(ink), "n_out_of_kg": len(ook),
        "top1": mean([r["top1"] for r in ink]), "top3": mean([r["top3"] for r in ink]),
        "top5": mean([r["top5"] for r in ink]), "mrr": mean([r["rr"] for r in ink]),
        "coverage": len(named) / len(ink) if ink else float("nan"),
        "selective_accuracy": mean([r["named_ok"] for r in named]),
        # share of ALL cases where the method commits (MEDIUM+ for dragnet, always for
        # baselines) to a wrong actor: the costly failure mode in attribution
        "confident_error_rate": sum(1 for r in confident if not r["named_ok"]) / len(rows)
        if rows else float("nan"),
        "out_of_kg_abstain": mean([r["named"] is None for r in ook]),
        "brier": mean([(p - float(ok)) ** 2 for p, ok in pairs]), "ece": ece(pairs),
        "brier_dist": mean([r["brier"] for r in rows]),
        "reliability": reliability(pairs), "grades": grades, "rows": rows,
    }


# ------------------------------------------------------------ false-flag stress test
def _exclusive_families(kg: KnowledgeGraph) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for c in kg.campaigns.values():
        for s in c.signals:
            if s.kind == SignalKind.FAMILY and kg.specificity(s) == 1.0:
                out[c.actor].append(s.value)
    return {a: sorted(set(v)) for a, v in out.items()}


def reference_rich_headers(kg: KnowledgeGraph) -> KnowledgeGraph:
    """Register one reference Rich-header fingerprint per actor (simulated): models the
    public sample corpora an adversary can copy a Rich header from (Olympic Destroyer
    copied a Lazarus one). Only the *planted* copies ever appear in evidence."""
    extra = [Campaign(f"RH-{norm(a)}", "reference sample Rich header (simulated)", a,
                      [Signal(SignalKind.RICH_HEADER, f"rh:ref-{norm(a)}")]) for a in kg.actors]
    return KnowledgeGraph(list(kg.campaigns.values()) + extra, kg.actor_meta, kg.meta)


def plant_false_flags(cases: list[Case], kg: KnowledgeGraph, level: int, seed: int = 7) -> list[Case]:
    """level 1: planted Rich header + decoy-language strings (forgeable only)
    level 2: level 1 + one exclusive decoy malware family (tool theft / code reuse)."""
    excl = _exclusive_families(kg)
    out = []
    for c in cases:
        if not c.truth:
            continue
        truth = next(iter(c.truth))
        tc = kg.country(truth)
        pool = sorted(a for a in excl if a not in c.truth and kg.country(a)
                      and kg.country(a) != tc and kg.country(a) in COUNTRY_LANG)
        if not pool:
            continue
        rng = random.Random(seed * 1_000_003 + zlib.crc32(c.case_id.encode()))
        decoy = rng.choice(pool)
        sigs = list(c.signals) + [
            Signal(SignalKind.RICH_HEADER, f"rh:ref-{norm(decoy)}", "planted"),
            Signal(SignalKind.LANGUAGE, f"lang:{COUNTRY_LANG[kg.country(decoy)]}", "planted")]
        if level >= 2:
            sigs.append(Signal(SignalKind.FAMILY, rng.choice(excl[decoy]), "planted"))
        out.append(Case(c.case_id, c.name, sigs, c.truth, dict(c.meta, decoy=decoy, level=level)))
    return out


def evaluate_false_flag(method: str, cases: list[Case], kg: KnowledgeGraph) -> dict:
    fn = METHODS[method]
    n = decoy_top = decoy_conf = truth_top = flagged = withheld = 0
    for c in cases:
        p = fn(c.signals, kg)
        decoy = c.meta["decoy"]
        n += 1
        leader = _top(p.scores)
        decoy_top += leader == decoy
        truth_top += leader in c.truth
        committed = p.named if p.grade is None else (p.named if p.grade in ("HIGH", "MEDIUM") else None)
        decoy_conf += committed == decoy
        flagged += p.flags > 0
        withheld += p.grade in ("LOW", "INSUFFICIENT") if p.grade else False
    f = lambda x: x / n if n else float("nan")  # noqa: E731
    return {"method": method, "n": n, "decoy_top1": f(decoy_top), "confident_decoy": f(decoy_conf),
            "truth_top1": f(truth_top), "flagged": f(flagged), "withheld": f(withheld)}


def false_alarm_rate(cases: list[Case], kg: KnowledgeGraph) -> float:
    fn = METHODS["dragnet"]
    clean = [c for c in cases if c.truth]
    return sum(fn(c.signals, kg).flags > 0 for c in clean) / len(clean) if clean else float("nan")


def fmt(x) -> str:
    if isinstance(x, float):
        return "n/a" if math.isnan(x) else f"{x:.3f}"
    return str(x)
