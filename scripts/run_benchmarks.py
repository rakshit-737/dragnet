"""Run the DRAGNET benchmarks on the downloaded public data and write results/.

Sections (``--only`` picks a subset; results are merged into results/benchmark.json):

  A1   ATT&CK v19.2 campaigns vs v19.2 group profiles (retrospective, leaky upper bound)
  A1LF A1 with leave-report-out profiles: group edges cited only by the campaign's own
       reports are removed before attribution (the controlled campaign-level protocol;
       the README headline uses the per-report set R)
  A2   v19.2 campaigns vs stale ATT&CK v10.1 profiles (open-world); 'later' subset =
       campaigns whose activity began after the v10.1 release
  A3   novel malware family attributed from its documented techniques only
  R    per-report ATT&CK cases (group x cited report): 5-fold leave-report-out and a
       temporal split by citation year; signal-family contribution; isotonic calibration
  G    comparison with Guru, Moss & Kochenderfer (2025), arXiv:2505.11547 (29 actors, mean rank)
  B    cross-release campaign union (ATT&CK 12.1-19.2, Enterprise+ICS+Mobile) and the
       rolling-origin protocol; Malpedia-labelled abuse.ch cases (B3)
  C    curated real case studies (demonstrations of rules designed from these cases)
  D    false-flag stress test (planted decoys on A1 cases)
  E1   ThreatFox export structure and IOC re-sighting
  E2   MalwareBazaar imphash genetics, time split
  E3   MalwareBazaar TLSH genetics, time split, radius chosen on a validation slice
  F    accuracy vs public reporting depth (APTnotes)
  K    APTMalware hash list vs MalwareBazaar metadata (literature check for Kida & Olukoya 2023)

Usage: python scripts/run_benchmarks.py [--only A1,A1LF,...] [--no-figures] [--render-only]
Heavy sections (B3, E2, E3, K) need the abuse.ch exports and run in the bench workflow.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from dragnet import bench
from dragnet import protocols as P
from dragnet.ach import assess
from dragnet.bench import METHODS, fmt
from dragnet.cases import addition_campaigns, load_real_cases
from dragnet.graph import TLSH_TAU, KnowledgeGraph
from dragnet.kg_build import (
    build_from_attack,
    enrich_bazaar,
    enrich_threatfox,
    family_actor_map,
    imphash_family_index,
)
from dragnet.models import Signal, SignalKind
from dragnet.paths import FIXTURES, RESULTS, data_dir
from dragnet.sources.abusech import iter_bazaar, iter_threatfox
from dragnet.sources.aptnotes import load_aptnotes, report_counts
from dragnet.sources.attack import load_attack
from dragnet.sources.misp import load_malpedia_families, load_threat_actors, norm

MAIN = ["dragnet", "ttp-jaccard", "ttp-cosine", "ttp-binary-bayes", "ioc-correlation", "code-only"]
ABL = ["dragnet", "dragnet-no-spec", "dragnet-no-ttpsim", "dragnet-no-ff"]
ALL_SECTIONS = ["A1", "A1LF", "A2", "A3", "R", "G", "B", "C", "D", "E1", "E2", "E3", "F", "K"]
ORDER = ["A1LF", "A1", "A2", "A3", "R", "G", "B", "C", "D", "E1", "E2", "E3", "F", "K"]


# ======================================================================== shared helpers
class Ctx:
    def __init__(self, d: Path):
        self.d = d
        self.attack = load_attack(d / "enterprise-attack-19.2.json")
        self.misp = load_threat_actors(d / "misp-threat-actor.json")
        self.malpedia = load_malpedia_families(d / "misp-malpedia.json")
        self.kg = self.build(self.attack)
        self.cases = bench.attack_campaign_cases(self.attack, self.attack)
        self.inv = {c.attack_id: k for k, c in self.attack.campaigns.items()}

    def build(self, attack, **kw) -> KnowledgeGraph:
        return build_from_attack(attack, misp=self.misp, malpedia=self.malpedia, **kw)


def strip_rows(s: dict) -> dict:
    return {k: v for k, v in s.items() if k != "rows"}


def add_intervals(s: dict, cluster=None) -> dict:
    """Exact Clopper-Pearson CIs for proportions; bootstrap (case or cluster) for top-1."""
    c, n, nk = s["counts"], s["n"], s["n_in_kg"]
    cp = P.clopper_pearson
    s["ci95"] = {
        "coverage": cp(c["named"], nk), "selective_accuracy": cp(c["named_ok"], c["named"]),
        "confident_error_rate": cp(c["confident_wrong"], n), "wrong_any_grade": cp(c["wrong_any"], n),
    }
    ink = [r for r in s["rows"] if r["in_kg"]]
    stat = lambda rs: sum(r["top1"] for r in rs if r["in_kg"]) / max(1, sum(r["in_kg"] for r in rs))
    if cluster:
        s["ci95"]["top1"] = P.cluster_bootstrap(ink, cluster, stat)
        s["top1_ci_kind"] = "cluster bootstrap"
    else:
        s["ci95"]["top1"] = P.cluster_bootstrap(ink, lambda r: r["case"], stat)
        s["top1_ci_kind"] = "case bootstrap"
    s["risk_coverage"] = P.risk_coverage([(r["p_leader"], r["leader_ok"]) for r in s["rows"]])
    return s


def grade_table(s: dict) -> dict:
    out = {}
    for g in ("HIGH", "MEDIUM", "LOW"):
        sel = [r for r in s["rows"] if r["grade"] == g and r["named"]]
        k = sum(r["named_ok"] for r in sel)
        out[g] = {"n": len(sel), "correct": k, "accuracy": k / len(sel) if sel else float("nan"),
                  "ci95": P.clopper_pearson(k, len(sel))}
    return out


def paired(summ: dict[str, dict], ref: str = "dragnet", cluster=None) -> dict:
    """Top-1 differences ref minus each method, with Holm adjustment across methods.

    Without ``cluster``: case bootstrap CI and a case-level sign-flip test (exact up to 20
    discordant cases, else Monte Carlo with p = (k+1)/(B+1)). With ``cluster`` (a row ->
    cluster-id function, e.g. the true group): a cluster bootstrap CI and a sign-flip test over
    per-cluster summed differences, matching the cluster-bootstrapped marginal CIs; the
    case-level result is kept under ``case_level`` for reference."""
    out = {}
    for m, s in summ.items():
        if m == ref:
            continue
        keep = [(a, b) for a, b in zip(summ[ref]["rows"], s["rows"]) if a["in_kg"]]
        diffs = [a["top1"] - b["top1"] for a, b in keep]
        bs = bench.paired_bootstrap_diff(summ[ref]["rows"], s["rows"])
        sf = P.sign_flip_test(diffs)
        if cluster is None:
            out[m] = {"diff": bs["diff"], "ci": bs["ci"], "ci_kind": "case bootstrap", **sf}
            continue
        cl = [cluster(a) for a, _ in keep]
        ci = P.cluster_bootstrap([{"d": d, "g": g} for d, g in zip(diffs, cl)], lambda r: r["g"],
                                 lambda rs: sum(r["d"] for r in rs) / len(rs))
        out[m] = {"diff": bs["diff"], "ci": list(ci), "ci_kind": "cluster bootstrap",
                  **P.cluster_sign_flip_test(diffs, cl),
                  "case_level": {"ci": bs["ci"], **sf}}
    adj = P.holm({m: v["p_one_sided"] for m, v in out.items()})
    for m in out:
        out[m]["p_holm"] = adj[m]
    if cluster is not None:
        adj_c = P.holm({m: v["case_level"]["p_one_sided"] for m, v in out.items()})
        for m in out:
            out[m]["case_level"]["p_holm"] = adj_c[m]
    return out


def rc_diffs(summ: dict[str, dict], cluster, ref: str = "dragnet", n_boot: int = 1000) -> dict:
    """Paired differences in selective risk at 20% coverage and in AURC (ref minus method),
    with cluster-bootstrap 95% CIs (negative = ref has the lower risk)."""
    def risk(pairs):
        rc = P.risk_coverage(pairs)
        return rc["risk_at"].get("0.2", float("nan")), rc["aurc"]
    out = {}
    ra = summ[ref]["rows"]
    for m, s in summ.items():
        if m == ref:
            continue
        rows = [{"a": (x["p_leader"], x["leader_ok"]), "b": (y["p_leader"], y["leader_ok"]), "g": cluster(x)}
                for x, y in zip(ra, s["rows"])]
        r20 = lambda rs: risk([r["a"] for r in rs])[0] - risk([r["b"] for r in rs])[0]
        au = lambda rs: risk([r["a"] for r in rs])[1] - risk([r["b"] for r in rs])[1]
        out[m] = {"risk20_diff": r20(rows), "risk20_ci": P.cluster_bootstrap(rows, lambda r: r["g"], r20, n_boot=n_boot),
                  "aurc_diff": au(rows), "aurc_ci": P.cluster_bootstrap(rows, lambda r: r["g"], au, n_boot=n_boot)}
    return out


def run_methods(methods, cases, kg_for_case) -> dict[str, dict]:
    """Evaluate methods where each case may need its own (leave-report-out) graph."""
    preds = {m: [] for m in methods}
    for c in cases:
        kg = kg_for_case(c)
        for m in methods:
            preds[m].append(METHODS[m](c.signals, kg))
    return preds


# ======================================================================== A1 / A1LF / A2 / A3
def sec_A1(cx: Ctx) -> dict:
    allm = list(dict.fromkeys(MAIN + ABL))
    summ = {m: add_intervals(bench.evaluate(m, cx.cases, cx.kg)) for m in allm}
    leak = []
    for c in cx.cases:
        gid = next(k for k, g in cx.attack.groups.items() if c.truth and g.name in c.truth)
        own = {cx.attack.software[s].name for s in cx.attack.software_of(cx.inv[c.case_id])}
        prof = {cx.attack.software[s].name for s in cx.attack.software_of(gid)}
        leak.append(bool(own & prof))
    ok_in_leak = sum(r["named_ok"] and lk for r, lk in zip(summ["dragnet"]["rows"], leak))
    return {"main": [summ[m] for m in MAIN], "ablation": [strip_rows(summ[m]) for m in ABL],
            "paired": paired({m: summ[m] for m in allm}), "grades": grade_table(summ["dragnet"]),
            "leak": {"cases_with_own_software_in_true_profile": sum(leak), "n": len(leak),
                     "dragnet_correct_named_among_them": ok_in_leak,
                     "dragnet_correct_named": summ["dragnet"]["counts"]["named_ok"]}}


def sec_A1LF(cx: Ctx) -> dict:
    allm = list(dict.fromkeys(MAIN + ABL))
    removed = []

    def kg_for(c):
        cid = cx.inv[c.case_id]
        held = P.campaign_refs(cx.attack, cid)
        a2 = P.drop_cited(cx.attack, held)
        removed.append(sum(len(v) for k, v in cx.attack.uses.items() if k in cx.attack.groups)
                       - sum(len(v) for k, v in a2.uses.items() if k in a2.groups))
        return cx.build(a2)

    preds = run_methods(allm, cx.cases, kg_for)
    summ = {m: add_intervals(bench.evaluate(m, cx.cases, cx.kg, preds[m])) for m in allm}
    return {"main": [summ[m] for m in MAIN], "ablation": [strip_rows(summ[m]) for m in ABL],
            "paired": paired({m: summ[m] for m in allm}), "grades": grade_table(summ["dragnet"]),
            "edges_removed_mean": sum(removed) / len(removed) if removed else 0,
            "edges_removed_total": sum(removed)}


def sec_A2(cx: Ctx) -> dict:
    p10 = cx.d / "enterprise-attack-10.1.json"
    attack10 = load_attack(p10)
    kg10 = cx.build(attack10)
    cases10 = bench.attack_campaign_cases(cx.attack, attack10)
    rel = attack10.released[:10]
    later = {c.case_id for c in cases10
             if (cx.attack.campaigns[cx.inv[c.case_id]].first_seen or "9999") >= rel}
    out = {"kg_version": attack10.version, "kg_released": attack10.released, "n_later": len(later),
           "main": [], "later": []}
    for m in MAIN:
        sm = add_intervals(bench.evaluate(m, cases10, kg10))
        out["main"].append(strip_rows(sm) | {"grades": grade_table(sm) if m == "dragnet" else {}})
        sub = [r for r in sm["rows"] if r["case"] in later]
        if sub:
            out["later"].append(strip_rows(add_intervals(bench.summarise(m, sub))))
    return out


def sec_A3(cx: Ctx) -> dict:
    cases3 = bench.novel_family_cases(cx.attack)
    summ = {m: add_intervals(bench.evaluate(m, cases3, cx.kg), cluster=lambda r: r["truth"][0])
            for m in ("dragnet", "ttp-jaccard", "ttp-cosine", "ttp-binary-bayes")}
    return {"main": [strip_rows(s) for s in summ.values()], "grades": grade_table(summ["dragnet"])}


# ======================================================================== R: per-report cases
R_METHODS = ["dragnet", "ttp-jaccard", "ttp-cosine", "ttp-binary-bayes", "ioc-correlation", "code-only",
             "dragnet-ttp-only", "dragnet-software-only", "dragnet-no-ttpsim", "dragnet-no-spec", "dragnet-no-ff"]
R_BASELINES = ["ttp-jaccard", "ttp-cosine", "ttp-binary-bayes", "ioc-correlation", "code-only"]


def _by_group(r: dict) -> str:
    return r["truth"][0] if r["truth"] else r["case"]


def sec_R(cx: Ctx, k: int = 5, cutoff_year: int = 2022) -> dict:
    cases = P.report_cases(cx.attack)
    by_group = _by_group
    # k-fold leave-report-out
    folds: dict[int, list] = defaultdict(list)
    for c in cases:
        folds[P.fold_of(c.meta["report"], k)].append(c)
    order, preds = [], {m: [] for m in R_METHODS}
    for f in range(k):
        held = {c.meta["report"] for c in folds[f]}
        kg = cx.build(P.drop_cited(cx.attack, held))
        for c in folds[f]:
            order.append(c)
            for m in R_METHODS:
                preds[m].append(METHODS[m](c.signals, kg))
    kf = {m: add_intervals(bench.evaluate(m, order, cx.kg, preds[m]), cluster=by_group) for m in R_METHODS}
    # temporal: profiles from reports published before cutoff_year only. Citations are dated
    # from their external_reference description (falling back to a year in the citation key).
    test = [c for c in cases if c.meta["year"] and c.meta["year"] >= cutoff_year]
    later = P.later_refs(cx.attack, cutoff_year)
    kg_t = cx.build(P.drop_cited(cx.attack, later))
    tp = {m: [METHODS[m](c.signals, kg_t) for c in test] for m in R_METHODS}
    tmp = {m: add_intervals(bench.evaluate(m, test, kg_t, tp[m]), cluster=by_group) for m in R_METHODS}
    # sensitivity: citations with no recoverable date ('n.d.', no year in the key) also held out
    later_nd = P.later_refs(cx.attack, cutoff_year, undated_as_later=True)
    kg_nd = cx.build(P.drop_cited(cx.attack, later_nd))
    tnd = {m: add_intervals(bench.evaluate(m, test, kg_nd, [METHODS[m](c.signals, kg_nd) for c in test]),
                            cluster=by_group) for m in R_METHODS}
    cited = {r for refs in cx.attack.uses_refs.values() for r in refs}
    dating = {"citations_on_uses_edges": len(cited),
              "dated_by_description": sum(1 for r in cited if cx.attack.ref_years.get(r) is not None),
              "dated_by_key_only": sum(1 for r in cited if cx.attack.ref_years.get(r) is None
                                       and P.ref_year(r) is not None),
              "undated": sum(1 for r in cited if P.ref_year(r, cx.attack) is None),
              "key_without_year_dated_later": sum(1 for r in later if P.ref_year(r) is None),
              "held_out_later": len(later), "held_out_with_undated": len(later_nd),
              "key_year_disagrees": sum(1 for r in cited if P.ref_year(r) is not None
                                        and cx.attack.ref_years.get(r) is not None
                                        and P.ref_year(r) != cx.attack.ref_years[r])}
    # isotonic calibration: fit on k-fold cases from before the cutoff, test on the temporal split
    cal_rows = [r for r, c in zip(kf["dragnet"]["rows"], order) if c.meta["year"] and c.meta["year"] < cutoff_year]
    iso = P.Isotonic().fit([r["p_leader"] for r in cal_rows], [float(r["leader_ok"]) for r in cal_rows])
    trows = tmp["dragnet"]["rows"]
    raw = [(min(1.0, r["p_leader"]), r["leader_ok"]) for r in trows]
    cal = [(iso(r["p_leader"]), r["leader_ok"]) for r in trows]
    brier = lambda ps: sum((p - float(o)) ** 2 for p, o in ps) / len(ps)

    def ci(ps, f, rows=trows):
        return P.cluster_bootstrap([{"p": p, "o": o, "g": by_group(r)} for (p, o), r in zip(ps, rows)],
                                   lambda x: x["g"], lambda xs: f([(x["p"], x["o"]) for x in xs]), n_boot=1000)

    def base_pairs(m):
        return [(min(1.0, r["p_leader"]), r["leader_ok"]) for r in tmp[m]["rows"]]
    calib = {"n_fit": len(cal_rows), "n_test": len(trows),
             "raw": {"ece": bench.ece(raw), "brier": brier(raw), "ece_ci": ci(raw, bench.ece),
                     "brier_ci": ci(raw, brier), "reliability": bench.reliability(raw)},
             "isotonic": {"ece": bench.ece(cal), "brier": brier(cal), "ece_ci": ci(cal, bench.ece),
                          "brier_ci": ci(cal, brier), "reliability": bench.reliability(cal)},
             "map": {"x": iso.x, "y": iso.y},
             "baselines_ece": {m: tmp[m]["ece"] for m in R_BASELINES},
             "baselines_ece_ci": {m: ci(base_pairs(m), bench.ece, tmp[m]["rows"]) for m in R_BASELINES}}
    return {"n_cases": len(cases), "n_groups": len({c.meta["group"] for c in cases}), "k": k,
            "cutoff_year": cutoff_year, "n_temporal": len(test), "dating": dating,
            "kfold": [strip_rows(kf[m]) for m in R_METHODS], "kfold_paired": paired(kf, cluster=by_group),
            "kfold_grades": grade_table(kf["dragnet"]),
            "kfold_rc_diff": rc_diffs({m: kf[m] for m in ["dragnet", *R_BASELINES]}, by_group),
            "temporal": [strip_rows(tmp[m]) for m in R_METHODS], "temporal_paired": paired(tmp, cluster=by_group),
            "temporal_grades": grade_table(tmp["dragnet"]),
            "temporal_rc_diff": rc_diffs({m: tmp[m] for m in ["dragnet", *R_BASELINES]}, by_group),
            "temporal_undated_later": [strip_rows(tnd[m]) for m in R_METHODS],
            "temporal_undated_later_paired": paired(tnd, cluster=by_group),
            "temporal_undated_later_grades": grade_table(tnd["dragnet"]),
            "calibration": calib}


# ======================================================================== G: Guru et al. 2025
GURU_ACTORS = ["APT17", "APT28", "APT29", "APT3", "APT32", "APT33", "APT39", "Ajax Security Team",
               "Cobalt Group", "Deep Panda", "Dragonfly", "FIN6", "FIN7", "Gamaredon Group", "Kimsuky",
               "Lazarus Group", "Magic Hound", "MuddyWater", "OilRig", "Sandworm Team", "TA505", "TeamTNT",
               "Threat Group-3390", "Tonto Team", "Tropic Trooper", "Turla", "Winnti Group", "Wizard Spider",
               "menuPass"]
GURU_PAPER = {"random": 15.0, "uniform prior": (10.68, 0.53), "expert prior": (7.75, 0.09),
              "HyDE + expert prior": (7.55, 0.21), "released single test (143 docs)": 12.67}


def _rank(scores: dict[str, float], truth: str, actors: list[str]) -> float:
    v = scores.get(truth, 0.0)
    above = sum(1 for a in actors if scores.get(a, 0.0) > v)
    ties = sum(1 for a in actors if scores.get(a, 0.0) == v)
    return above + (ties + 1) / 2


G_METHODS = ["guru-uniform", "guru-report-prior", "ttp-binary-bayes", "ttp-jaccard", "dragnet-ttp-only",
             "dragnet-software-only", "dragnet"]


def sec_G(cx: Ctx, seeds: int = 10) -> dict:
    names = {g.name for g in cx.attack.groups.values()}
    actors = [a for a in GURU_ACTORS if a in names]
    cases = [c for c in P.report_cases(cx.attack) if next(iter(c.truth)) in actors]
    by_actor: dict[str, list] = defaultdict(list)
    for c in cases:
        by_actor[next(iter(c.truth))].append(c)
    methods = G_METHODS
    per_seed = {m: [] for m in methods}
    top1 = {m: [] for m in methods}
    pooled: list[dict] = []          # one row per (seed, test case): rank under every method
    for seed in range(seeds):
        rng = random.Random(seed)
        train, test = [], []
        for a in actors:
            cs = sorted(by_actor[a], key=lambda c: c.case_id)
            rng.shuffle(cs)
            n_test = max(1, round(0.1 * len(cs)))
            n_val = round(0.2 * len(cs))
            test += cs[:n_test]
            train += cs[n_test + n_val:]
        # Guru et al. scorer: P(t | a) from technique counts in training reports
        counts: dict[str, Counter] = defaultdict(Counter)
        nrep: Counter = Counter()
        for c in train:
            a = next(iter(c.truth))
            nrep[a] += 1
            counts[a].update(s.value for s in c.signals if s.kind == SignalKind.TTP)
        ptech = {a: {t: n / sum(cnt.values()) for t, n in cnt.items()} for a, cnt in counts.items()}
        prior = {a: nrep[a] / sum(nrep.values()) for a in actors}
        held = {c.meta["report"] for c in cases if c not in train}
        kg = cx.build(P.drop_cited(cx.attack, held))
        ranks = {m: [] for m in methods}
        for c in test:
            truth = next(iter(c.truth))
            doc = {s.value for s in c.signals if s.kind == SignalKind.TTP}
            sc = {a: sum(ptech.get(a, {}).get(t, 0.0) for t in doc) for a in actors}
            res = {"guru-uniform": sc, "guru-report-prior": {a: sc[a] * prior[a] for a in actors}}
            for m in methods[2:]:
                res[m] = METHODS[m](c.signals, kg).scores
            row = {"seed": seed, "case": c.case_id, "actor": truth}
            for m in methods:
                row[m] = _rank(res[m], truth, actors)
                ranks[m].append(row[m])
            pooled.append(row)
        for m in methods:
            per_seed[m].append(statistics.mean(ranks[m]))
            top1[m].append(sum(r == 1 for r in ranks[m]) / len(ranks[m]))
    out = {"actors": actors, "n_reports": len(cases), "seeds": seeds,
           "reports_per_actor": {a: len(v) for a, v in by_actor.items()}, "paper": GURU_PAPER, "ours": {},
           "n_pooled": len(pooled)}
    by_actor_row = lambda r: r["actor"]
    for m in methods:
        out["ours"][m] = {"mean_rank": statistics.mean(per_seed[m]), "sd": statistics.pstdev(per_seed[m]),
                          "top1": statistics.mean(top1[m]),
                          # pooled over the 10 splits; resampling whole actors
                          "ci95_actor_cluster": P.cluster_bootstrap(
                              pooled, by_actor_row, lambda rs, m=m: sum(r[m] for r in rs) / len(rs))}
    # paired: rank of the comparison method minus DRAGNET's rank (positive = DRAGNET ranks the true
    # actor higher), per-actor sign-flip over the pooled cases
    out["paired_vs_dragnet"] = {}
    for m in methods:
        if m == "dragnet":
            continue
        d = [r[m] - r["dragnet"] for r in pooled]
        ci = P.cluster_bootstrap([{"d": x, "g": r["actor"]} for x, r in zip(d, pooled)], lambda r: r["g"],
                                 lambda rs: sum(r["d"] for r in rs) / len(rs))
        out["paired_vs_dragnet"][m] = {"rank_diff": statistics.mean(d), "ci": list(ci),
                                       **P.cluster_sign_flip_test(d, [r["actor"] for r in pooled]),
                                       "splits_dragnet_better": sum(a < b for a, b in zip(per_seed["dragnet"], per_seed[m]))}
    adj = P.holm({m: v["p_one_sided"] for m, v in out["paired_vs_dragnet"].items()})
    for m, v in out["paired_vs_dragnet"].items():
        v["p_holm"] = adj[m]
    return out


# ======================================================================== B: case-set enlargement
def sec_B(cx: Ctx) -> dict:
    from dragnet.casesets import pick_release
    rels = ["12.1", "13.1", "14.1", "15.1", "16.1", "17.1", "18.1"]
    info: dict[str, dict] = {}
    released: dict[str, str] = {}
    per_release_attr: dict[str, int] = {}
    kgs: dict[str, KnowledgeGraph] = {}
    for v in rels:
        a = load_attack(cx.d / f"enterprise-attack-{v}.json")
        released[v] = a.released
        per_release_attr[v] = len(a.attributed)
        for cid in a.attributed:
            info.setdefault(cid, {"first_version": v})
        kgs[v] = cx.build(a)
        del a
    extra = [cx.d / "ics-attack-19.2.json", cx.d / "mobile-attack-19.2.json"]
    a_all = load_attack(cx.d / "enterprise-attack-19.2.json", *[p for p in extra if p.exists()])
    per_release_attr["19.2 (enterprise+ics+mobile)"] = len(a_all.attributed)
    union = sorted(set(info) | set(a_all.attributed))
    cases = bench.attack_campaign_cases(a_all, a_all)
    inv = {c.attack_id: k for k, c in a_all.campaigns.items()}
    kg_all = cx.build(a_all)
    new_ids = [c.case_id for c in cases if c.case_id not in {x.case_id for x in cx.cases}]
    # leave-report-out on the union (Enterprise+ICS+Mobile graph)
    lf = {m: [] for m in ("dragnet", "ioc-correlation", "code-only", "ttp-jaccard")}
    for c in cases:
        kg = cx.build(P.drop_cited(a_all, P.campaign_refs(a_all, inv[c.case_id])))
        for m in lf:
            lf[m].append(METHODS[m](c.signals, kg))
    b1s = {m: add_intervals(bench.evaluate(m, cases, kg_all, lf[m])) for m in lf}
    b1 = [strip_rows(v) for v in b1s.values()]

    # rolling origin: newest release published before the campaign object was created
    class _R:
        def __init__(self, v, r):
            self.version, self.released = v, r
    ro_rows = {m: [] for m in ("dragnet", "ioc-correlation", "code-only")}
    ro_cases, mapping = [], Counter()
    for c in cases:
        created = a_all.campaigns[inv[c.case_id]].created or ""
        r = pick_release([_R(v, released[v]) for v in rels], created)
        if r is None:
            continue
        kg = kgs[r.version]
        truth = {n for n in c.truth if n in kg.actors}
        cc = bench.Case(c.case_id, c.name, c.signals, truth, c.meta)
        ro_cases.append(cc)
        mapping[r.version] += 1
        for m in ro_rows:
            ro_rows[m].append(METHODS[m](c.signals, kg))
    b2s = {m: add_intervals(bench.evaluate(m, ro_cases, kg_all, ro_rows[m])) for m in ro_rows} if ro_cases else {}
    b2 = [strip_rows(v) for v in b2s.values()]
    out = {"attributed_per_release": per_release_attr, "union_campaigns": len(union),
           "B1_cases": len(cases), "B1_new_case_ids": new_ids, "B1": b1, "B1_paired": paired(b1s),
           "B2_release_used": dict(mapping), "B2": b2, "B2_paired": paired(b2s) if b2s else {}}
    b3 = cx.d / "malpedia-families.json"
    if b3.exists() and (cx.d / "threatfox-full.json.zip").exists() and (cx.d / "bazaar-full.csv.zip").exists():
        out["B3"] = sec_B3(cx)
    return out


def sec_B3(cx: Ctx, cutoff: str = "2024-01-01", seeds: int = 5) -> dict:
    from dragnet.casesets import actor_resolver, malpedia_cases
    from dragnet.sources.malpedia import load_actor_synonyms, load_families
    fams = load_families(cx.d / "malpedia-families.json")
    syn = load_actor_synonyms(cx.d / "malpedia-actors.json")
    a14 = load_attack(cx.d / "enterprise-attack-14.1.json")      # released 2023-11-14 < cutoff
    resolver = actor_resolver(a14, cx.misp, syn)
    tf = list(iter_threatfox(cx.d / "threatfox-full.json.zip"))
    bz = [s for s in iter_bazaar(cx.d / "bazaar-full.csv.zip") if s.signature and (s.imphash or s.tlsh)]
    pre_bz = [s for s in bz if s.first_seen < cutoff]
    gidx = imphash_family_index(pre_bz)
    kg = build_from_attack(a14, misp=cx.misp, malpedia=cx.malpedia)
    kg, _ = enrich_bazaar(kg, a14, pre_bz, global_index=gidx, malpedia=cx.malpedia)
    kg, _ = enrich_threatfox(kg, a14, [i for i in tf if i.first_seen < cutoff], malpedia=cx.malpedia)
    methods = ["dragnet", "ioc-correlation", "code-only", "dragnet-infra-only", "dragnet-genetics-only"]
    res = {"cutoff": cutoff, "graph": f"ATT&CK v{a14.version} + pre-cutoff abuse.ch", "seeds": seeds,
           "label_agreement": None, "variants": {}}
    for variant, with_name in (("artifacts only", False), ("artifacts + family name", True)):
        per_seed = {m: [] for m in methods}
        last = None
        for seed in range(seeds):
            cases = malpedia_cases(fams, resolver, tf, bz, cutoff, with_family_name=with_name, seed=seed)
            sm = {m: bench.evaluate(m, cases, kg) for m in methods}
            for m in methods:
                per_seed[m].append(sm[m])
            last = (cases, sm)
        cases, sm = last
        res["variants"][variant] = {
            "n_cases": len(cases), "n_labelled_in_graph": sum(1 for c in cases if c.truth),
            "per_method": {m: {k: statistics.mean(s[k] for s in per_seed[m]) for k in
                               ("top1", "coverage", "selective_accuracy", "confident_error_rate",
                                "wrong_any_grade", "out_of_kg_abstain")} for m in methods},
            "seed0_ci": {m: add_intervals(sm[m])["ci95"] for m in methods}}
    # label noise: Malpedia actor vs ATT&CK v14.1 family->actor for families both know
    fam_attack = family_actor_map(a14, 10, cx.malpedia)
    agree = total = 0
    for f in fams.values():
        if len(f.attribution) != 1:
            continue
        g = resolver.get(norm(f.attribution[0]))
        ga = next((fam_attack[norm(n)] for n in f.names if norm(n) in fam_attack), None)
        if g and ga:
            total += 1
            agree += g in ga
    res["label_agreement"] = {"families_in_both": total, "agree": agree}
    return res


# ======================================================================== C / D / F
def run_curated(cx: Ctx, mode: str) -> list[dict]:
    attack = cx.attack
    names = {g.attack_id: g.name for g in attack.groups.values()}
    out = []
    for case in load_real_cases(FIXTURES / "real_cases", attack):
        hide = set(case.novel_software) if mode == "time-of-incident" else set()
        base = cx.build(attack, exclude_software=hide)
        kg = KnowledgeGraph(list(base.campaigns.values()) + addition_campaigns(case, attack),
                            base.actor_meta, base.meta)
        a = assess(case.case_id, case.signals, kg)
        truth = {names[g] for g in case.ground_truth if g in names}
        ranked = a.ranked_actors
        rank = next((i + 1 for i, x in enumerate(ranked) if x in truth), None)
        if case.expected == "attribute":
            ok = a.leading in truth
        elif case.expected == "withhold":
            ok = bool(a.false_flag_indicators) and a.confidence.value in ("LOW", "INSUFFICIENT")
        else:
            ok = a.leading is None
        base_preds = {m: METHODS[m](case.signals, kg) for m in ("ttp-jaccard", "ioc-correlation", "code-only")}

        def verdict(p):
            if p.named:
                return p.named
            tied = bench._tied_top(p.scores)
            return f"tie among {len(tied)} (abstain)" if len(tied) > 1 else None
        out.append({
            "case": case.case_id, "title": case.title, "mode": mode, "truth": sorted(truth),
            "false_flag": case.false_flag, "expected": case.expected, "leading": a.leading,
            "confidence": a.confidence.value, "truth_rank": rank,
            "top_score": max((h.score for h in a.hypotheses if h.hypothesis in ranked[:1]), default=0.0),
            "flags": a.false_flag_indicators, "notes": a.notes, "behaved_as_expected": ok,
            "baselines": {m: verdict(p) for m, p in base_preds.items()},
        })
    return out


def sec_C(cx: Ctx) -> dict:
    return {mode: run_curated(cx, mode) for mode in ("time-of-incident", "retrospective")}


def sec_D(cx: Ctx) -> dict:
    kg, cases = cx.kg, cx.cases
    kg_rh = bench.reference_rich_headers(kg)
    meth = MAIN + ["dragnet-no-ff"]
    fa = bench.false_alarm_rate(cases, kg_rh)
    n_clean = sum(1 for c in cases if c.truth)
    res = {"false_alarm_rate_clean": fa, "false_alarm_n": n_clean,
           "false_alarm_ci": P.clopper_pearson(round(fa * n_clean), n_clean), "seeds": list(range(10))}
    for level in (1, 2):
        planted = bench.plant_false_flags(cases, kg, level)
        res[f"level{level}"] = [bench.evaluate_false_flag(m, planted, kg_rh) for m in meth]
        r7 = next(r for r in res[f"level{level}"] if r["method"] == "dragnet")
        k = round(r7["confident_decoy"] * r7["n"])
        res[f"level{level}_dragnet_ci"] = P.clopper_pearson(k, r7["n"])
    # per (case, seed) outcomes for a paired bootstrap of full engine vs no false-flag rules
    for level in (1, 2):
        per = {m: [] for m in meth}
        cells = []
        for sd in res["seeds"]:
            planted = bench.plant_false_flags(cases, kg, level, seed=sd)
            for c in planted:
                row = {"case": c.case_id, "seed": sd}
                for m in ("dragnet", "dragnet-no-ff"):
                    p = METHODS[m](c.signals, kg_rh)
                    committed = p.named if p.grade in ("HIGH", "MEDIUM") else None
                    row[m] = float(committed == c.meta["decoy"])
                cells.append(row)
            for m in meth:
                per[m].append(bench.evaluate_false_flag(m, planted, kg_rh)["confident_decoy"])
        res[f"level{level}_seeds"] = {m: {"mean": statistics.mean(v), "min": min(v), "max": max(v)}
                                      for m, v in per.items()}
        diff = lambda rs: statistics.mean(r["dragnet-no-ff"] - r["dragnet"] for r in rs)
        res[f"level{level}_ff_effect"] = {"mean_reduction": diff(cells),
                                          "ci95_case_cluster": P.cluster_bootstrap(cells, lambda r: r["case"], diff)}
    return res


def sec_F(cx: Ctx) -> dict:
    reports = load_aptnotes(cx.d / "APTnotes.csv")
    rows = bench.evaluate("dragnet", cx.cases, cx.kg)["rows"]
    out = {"aptnotes_reports_indexed": len(reports),
           "years": dict(sorted(Counter(r.year for r in reports).items()))}
    for label, meta in (("ATT&CK aliases only", build_from_attack(cx.attack).actor_meta),
                        ("ATT&CK + MISP aliases", cx.kg.actor_meta)):
        counts = report_counts(reports, meta)
        for r in rows:
            r["_n"] = max((counts.get(t, 0) for t in r["truth"]), default=0)
        b = {"0 reports": [r for r in rows if r["_n"] == 0],
             "1-5 reports": [r for r in rows if 1 <= r["_n"] <= 5],
             ">5 reports": [r for r in rows if r["_n"] > 5]}
        zero, some = b["0 reports"], [r for r in rows if r["_n"] > 0]
        out[label] = {"buckets": {k: {"n": len(v), "top1": sum(r["top1"] for r in v) / len(v) if v else float("nan")}
                                  for k, v in b.items()},
                      "fisher_p_zero_vs_some": _fisher([round(r["top1"]) for r in zero],
                                                       [round(r["top1"]) for r in some])}
    return out


def _fisher(a: list[int], b: list[int]) -> float:
    """Two-sided Fisher exact test on 2x2 (correct/incorrect x group a/b)."""
    a1, a0, b1, b0 = sum(a), len(a) - sum(a), sum(b), len(b) - sum(b)
    n, r1, c1 = a1 + a0 + b1 + b0, a1 + a0, a1 + b1
    if not n:
        return float("nan")
    p = lambda x: math.comb(c1, x) * math.comb(n - c1, r1 - x) / math.comb(n, r1)
    obs = p(a1)
    return min(1.0, sum(p(x) for x in range(max(0, r1 + c1 - n), min(r1, c1) + 1) if p(x) <= obs + 1e-12))


# ======================================================================== E: abuse.ch
def sec_E1(cx: Ctx) -> dict:
    fam = family_actor_map(cx.attack, 3, cx.malpedia)
    vals: Counter = Counter()
    rows = []
    n = 0
    for i in iter_threatfox(cx.d / "threatfox-full.json.zip"):
        n += 1
        vals[i.value] += 1
        key = norm(i.malware_printable)
        if key not in fam and norm(i.malware.split(".", 1)[-1]) not in fam:
            continue
        rows.append((i.first_seen, i.ioc_type, i.value, i.malware_printable))
    rows.sort()
    types = Counter(t for _, t, _, _ in rows)
    net = [(t, v.rsplit(":", 1)[0] if ty == "ip:port" else v, f) for t, ty, v, f in rows
           if ty in ("ip:port", "domain")]
    cut = net[len(net) // 2][0] if net else ""
    before = {v for t, v, _ in net if t < cut}
    after = [(v, f) for t, v, f in net if t >= cut]
    return {"rows": n, "distinct_values": len(vals), "share_values_in_one_row": sum(1 for c in vals.values() if c == 1) / len(vals),
            "actor_family_iocs": len(rows), "ioc_types": dict(types), "network_iocs": len(net),
            "network_cutoff": cut, "network_span": [net[0][0][:10], net[-1][0][:10]] if net else [],
            "network_after": len(after), "network_after_seen_before": sum(1 for v, _ in after if v in before),
            "top_families": Counter(f for *_, f in rows).most_common(10)}


def _family_stats(recs: list[dict], key: str) -> dict:
    """Sample-level and per-family macro accuracy with family- and imphash-clustered CIs."""
    cov = [r for r in recs if r[key]]
    acc = lambda rs: (sum(r[key + "_ok"] for r in rs if r[key]) / max(1, sum(1 for r in rs if r[key]))) \
        if any(r[key] for r in rs) else float("nan")
    fams = defaultdict(list)
    for r in recs:
        fams[r["family"]].append(r)
    macro_vals = [acc(v) for v in fams.values() if any(r[key] for r in v)]
    return {"n": len(recs), "coverage": len(cov) / len(recs) if recs else float("nan"),
            "selective_accuracy": acc(recs),
            "ci95_family_cluster": P.cluster_bootstrap(recs, lambda r: r["family"], acc, n_boot=1000),
            "ci95_cluster_key": P.cluster_bootstrap(recs, lambda r: r["cluster"], acc, n_boot=1000),
            "macro_family_accuracy": statistics.mean(macro_vals) if macro_vals else float("nan"),
            "families_covered": len(macro_vals), "distinct_clusters_covered": len({r["cluster"] for r in cov})}


def sec_E2(cx: Ctx, cutoff: str = "2024-01-01") -> dict:
    t0 = time.time()
    attack, malpedia = cx.attack, cx.malpedia
    fam = family_actor_map(attack, 3, malpedia)
    rows = [s for s in iter_bazaar(cx.d / "bazaar-full.csv.zip") if s.imphash and s.signature]
    gidx = imphash_family_index([s for s in rows if s.first_seen < cutoff])
    apt = [s for s in rows if norm(s.signature) in fam]
    train = [s for s in apt if s.first_seen < cutoff]
    test = [s for s in apt if s.first_seen >= cutoff]
    kg0 = build_from_attack(attack, malpedia=malpedia, language_signals=False)
    res = {"rows_with_imphash_and_label": len(rows), "apt_family_samples": len(apt), "train": len(train),
           "test": len(test), "cutoff": cutoff, "test_families": Counter(s.signature for s in test).most_common(8),
           "test_distinct_imphash": len({s.imphash for s in test})}
    for variant, gi in (("collision-filtered", gidx), ("unfiltered", None)):
        kg, hits = enrich_bazaar(kg0, attack, train, global_index=gi, malpedia=malpedia)
        cache: dict[str, tuple] = {}
        recs = []
        for s in test:
            truth = fam[norm(s.signature)]
            if s.imphash not in cache:
                sigs = [Signal(SignalKind.IMPHASH, s.imphash, s.sha256)]
                a = assess(s.sha256, sigs, kg)
                cache[s.imphash] = (a.leading, a.confidence.value, METHODS["code-only"](sigs, kg).named)
            leading, grade, base = cache[s.imphash]
            med = leading if grade in ("HIGH", "MEDIUM") else None
            recs.append({"family": s.signature, "cluster": s.imphash,
                         "dragnet": leading, "dragnet_ok": leading in truth if leading else False,
                         "medium": med, "medium_ok": med in truth if med else False,
                         "lookup": base, "lookup_ok": base in truth if base else False})
        nowc = [r for r in recs if norm(r["family"]) != "wannacry"]
        res[variant] = {"families_indexed": len(hits),
                        "dragnet": _family_stats(recs, "dragnet"), "dragnet_medium_plus": _family_stats(recs, "medium"),
                        "lookup": _family_stats(recs, "lookup"),
                        "dragnet_excl_wannacry": _family_stats(nowc, "dragnet"),
                        "medium_plus_excl_wannacry": _family_stats(nowc, "medium"),
                        "medium_plus_wannacry_share": (sum(1 for r in recs if r["medium"] and norm(r["family"]) == "wannacry")
                                                       / max(1, sum(1 for r in recs if r["medium"])))}
    res["seconds"] = round(time.time() - t0, 1)
    return res


def sec_E3(cx: Ctx, cutoff: str = "2024-01-01", val_start: str = "2023-07-01",
           collision_sample: int = 100_000) -> dict:
    """TLSH genetics: pre-cutoff digests of actor-specific families -> fuzzy graph signals."""
    from dragnet.casesets import enrich_tlsh
    from dragnet.tlsh import TlshIndex
    from dragnet.tlsh_np import NumpyTlshIndex
    t0 = time.time()
    attack, malpedia = cx.attack, cx.malpedia
    fam = family_actor_map(attack, 3, malpedia)
    rows = [s for s in iter_bazaar(cx.d / "bazaar-full.csv.zip") if s.tlsh and s.signature]
    rng = random.Random(0)

    def collision_index(before: str) -> NumpyTlshIndex:
        pool = [s for s in rows if s.first_seen < before]
        pool = pool if len(pool) <= collision_sample else rng.sample(pool, collision_sample)
        idx = NumpyTlshIndex()
        idx.extend((s.tlsh, norm(s.signature)) for s in pool)
        return idx

    def build(train, gidx, tau):
        # newest 1000 training samples per family bound the collision checks per family
        per: dict[str, list] = defaultdict(list)
        for s in sorted(train, key=lambda s: s.first_seen, reverse=True):
            if len(per[s.signature]) < 1000:
                per[s.signature].append(s)
        train = [s for v in per.values() for s in v]
        kg0 = build_from_attack(attack, malpedia=malpedia, language_signals=False)
        kg, _hits = enrich_tlsh(kg0, fam, train, global_index=gidx, tau=tau)
        npi = NumpyTlshIndex()
        npi.extend((s.value, c.id) for c in kg.campaigns.values() for s in c.signals if s.kind == SignalKind.TLSH)
        kg.tlsh_index = npi
        return kg

    def evaluate(kg, test, gidx_lookup, tau):
        recs, cache = [], {}
        for s in test:
            truth = fam[norm(s.signature)]
            if s.tlsh not in cache:
                a = assess(s.sha256, [Signal(SignalKind.TLSH, s.tlsh, s.sha256)], kg)
                nn = gidx_lookup.nearest(s.tlsh, k=1, max_dist=tau)
                lk = fam.get(nn[0][1]) if nn else None
                cache[s.tlsh] = (a.leading, a.confidence.value, next(iter(lk)) if lk and len(lk) == 1 else None)
            leading, grade, look = cache[s.tlsh]
            med = leading if grade in ("HIGH", "MEDIUM") else None
            recs.append({"family": s.signature, "cluster": s.signature, "dragnet": leading,
                         "dragnet_ok": leading in truth if leading else False, "medium": med,
                         "medium_ok": med in truth if med else False, "lookup": look,
                         "lookup_ok": look in truth if look else False})
        return recs

    apt = [s for s in rows if norm(s.signature) in fam]
    # 1) choose tau on a validation slice (train < val_start, validate on [val_start, cutoff))
    g_val = collision_index(val_start)
    v_train = [s for s in apt if s.first_seen < val_start]
    v_test = [s for s in apt if val_start <= s.first_seen < cutoff]
    v_test = v_test if len(v_test) <= 3000 else random.Random(1).sample(v_test, 3000)
    choice = {}
    for tau in (30, 50, 70, 100):
        recs = evaluate(build(v_train, g_val, tau), v_test, g_val, tau)
        cov = [r for r in recs if r["dragnet"]]
        ok = sum(r["dragnet_ok"] for r in cov)
        choice[tau] = {"coverage": len(cov) / max(1, len(recs)), "selective_accuracy": ok / max(1, len(cov)),
                       "net": ok - 2 * (len(cov) - ok)}
    tau = max(choice, key=lambda t: (choice[t]["net"], -t))
    # 2) final time split
    g = collision_index(cutoff)
    train = [s for s in apt if s.first_seen < cutoff]
    test = [s for s in apt if s.first_seen >= cutoff]
    kg = build(train, g, tau)
    recs = evaluate(kg, test, g, tau)
    # 3) false alarms: post-cutoff samples of families with no actor mapping
    clean = [s for s in rows if s.first_seen >= cutoff and norm(s.signature) not in fam]
    clean = clean if len(clean) <= 3000 else random.Random(2).sample(clean, 3000)
    fa = [assess(s.sha256, [Signal(SignalKind.TLSH, s.tlsh, s.sha256)], kg) for s in clean]
    # 4) recall of the stdlib banded index vs exact search on the same graph digests
    band = TlshIndex(exact_below=0)
    band.extend((s.value, c.id) for c in kg.campaigns.values() for s in c.signals if s.kind == SignalKind.TLSH)
    qs = random.Random(3).sample(test, min(300, len(test)))
    pairs = found = 0
    for s in qs:
        ex = {(d, dig) for d, _, dig in kg.tlsh_index.nearest(s.tlsh, k=10**9, max_dist=tau)}
        bd = {(d, dig) for d, _, dig in band.nearest(s.tlsh, k=10**9, max_dist=tau, exact=False)}
        pairs += len(ex)
        found += len(ex & bd)
    nowc = [r for r in recs if norm(r["family"]) != "wannacry"]
    return {"cutoff": cutoff, "validation": {"window": [val_start, cutoff], "n": len(v_test),
                                             "by_tau": choice, "chosen_tau": tau},
            "rows_with_tlsh_and_label": len(rows), "train": len(train), "test": len(test),
            "collision_index_size": len(g), "graph_digests": len(kg.tlsh_index),
            "dragnet": _family_stats(recs, "dragnet"), "dragnet_medium_plus": _family_stats(recs, "medium"),
            "nn_lookup": _family_stats(recs, "lookup"), "dragnet_excl_wannacry": _family_stats(nowc, "dragnet"),
            "false_alarm": {"n_clean": len(fa), "named_any": sum(1 for a in fa if a.leading) / max(1, len(fa)),
                            "named_medium_plus": sum(1 for a in fa if a.confidence.value in ("HIGH", "MEDIUM"))
                            / max(1, len(fa))},
            "band_index_recall": {"queries": len(qs), "true_pairs": pairs,
                                  "recall": found / pairs if pairs else float("nan")},
            "seconds": round(time.time() - t0, 1)}


# ======================================================================== K: Kida & Olukoya overlap
def sec_K(cx: Ctx) -> dict:
    """APTMalware (Kida & Olukoya, IEEE Access 2023, doi:10.1109/ACCESS.2022.3233403): how many of the
    dataset's SHA-256s the MalwareBazaar metadata export knows (hash intersection only)."""
    with (cx.d / "aptmalware-overview.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    group_of: dict[str, str] = {}
    for r in rows:
        h = (r.get("SHA256") or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", h):
            group_of.setdefault(h, (r.get("APT-group") or "").strip())
    found: set[str] = set()
    n_bazaar = 0
    for smp in iter_bazaar(cx.d / "bazaar-full.csv.zip"):
        n_bazaar += 1
        if smp.sha256 in group_of:
            found.add(smp.sha256)
    return {"overview_rows": len(rows), "distinct_sha256": len(group_of), "bazaar_rows": n_bazaar,
            "in_bazaar": len(found), "in_bazaar_by_group": dict(sorted(Counter(group_of[h] for h in found).items()))}


# ======================================================================== figures
# One colour per method across every figure (categorical palette in fixed slot order, validated for
# colour-vision deficiency on the adjacent pairs each figure draws); an ablation that would need a
# 9th hue reuses its parent's colour with a hatch. Values are printed on every bar.
METHOD_STYLE = {"dragnet": ("#2a78d6", None), "ioc-correlation": ("#eb6834", None), "code-only": ("#1baf7a", None),
                "ttp-cosine": ("#eda100", None), "ttp-jaccard": ("#e87ba4", None),
                "dragnet-no-ttpsim": ("#008300", None), "dragnet-no-spec": ("#4a3aa7", None),
                "dragnet-software-only": ("#e34948", None), "dragnet-no-ff": ("#2a78d6", "///")}
METHOD_LABEL = {"ttp-cosine": "ttp-cosine (= DRAGNET TTP-only)"}


def figures(res: dict, outdir: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - skipping figures")
        return
    outdir.mkdir(parents=True, exist_ok=True)
    ink, muted, surface, grid = "#0b0b0b", "#52514e", "#fcfcfb", "#e4e3df"
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": muted, "axes.labelcolor": ink,
                         "xtick.color": muted, "ytick.color": muted, "figure.facecolor": surface,
                         "axes.facecolor": surface, "savefig.facecolor": surface, "hatch.color": surface,
                         "hatch.linewidth": 1.2})

    def bars(ax, groups, labels, methods, getter, title, err=None, err_label="95% CI"):
        """Grouped bars; ``err(g, m)`` -> (lo, hi) draws whiskers; values are printed above them."""
        width = 0.84 / len(methods)
        for i, m in enumerate(methods):
            col, hatch = METHOD_STYLE.get(m, ("#888888", None))
            xs = [j + (i - (len(methods) - 1) / 2) * width for j in range(len(groups))]
            vals = [getter(g, m) for g in groups]
            ax.bar(xs, vals, width, color=col, hatch=hatch, edgecolor=surface, linewidth=1.5,
                   label=METHOD_LABEL.get(m, m), zorder=2)
            tops = list(vals)
            if err:
                lo_hi = [err(g, m) for g in groups]
                ok = [k for k, v in enumerate(lo_hi) if v and not any(math.isnan(x) for x in v)]
                if ok:
                    ax.errorbar([xs[k] for k in ok], [vals[k] for k in ok],
                                yerr=[[max(0.0, vals[k] - lo_hi[k][0]) for k in ok],
                                      [max(0.0, lo_hi[k][1] - vals[k]) for k in ok]],
                                fmt="none", ecolor=ink, elinewidth=0.9, capsize=2, zorder=3)
                    for k in ok:
                        tops[k] = max(vals[k], lo_hi[k][1])
            for x, v, t in zip(xs, vals, tops):
                ax.text(x, t + 0.015, f"{v:.2f}", ha="center", va="bottom", fontsize=6.5, color=ink)
        ax.set_xticks(range(len(groups)), labels)
        ax.set_ylim(0, 1.12)
        ax.set_title(title, fontsize=9.5, color=ink, loc="left", pad=30)
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", color=grid, linewidth=0.6, zorder=0)
        ax.set_axisbelow(True)
        ax.legend(frameon=False, fontsize=7.5, ncol=min(len(methods), 4), loc="lower left",
                  bbox_to_anchor=(0, 1.0), borderaxespad=0.2, handlelength=1.6)
        if err:
            ax.annotate(f"whiskers: {err_label}", xy=(1.0, 0), xycoords="axes fraction", xytext=(0, -34),
                        textcoords="offset points", ha="right", va="top", fontsize=7, color=muted)

    if "A1LF" in res:
        a = {s["method"]: s for s in res["A1LF"]["main"]}
        ms = [m for m in ("dragnet", "ioc-correlation", "code-only", "ttp-cosine", "ttp-jaccard") if m in a]
        metrics = [("top1", "top-1"), ("coverage", "coverage"), ("wrong_any_grade", "wrong actor named\n(any grade)"),
                   ("confident_error_rate", "wrong actor at\nMEDIUM+ / committed")]
        fig, ax = plt.subplots(figsize=(8, 4.4))
        bars(ax, [k for k, _ in metrics], [lbl for _, lbl in metrics], ms, lambda k, m: a[m][k],
             f"ATT&CK campaigns, leave-report-out profiles (A1-LF, n={a['dragnet']['n']})",
             err=lambda k, m: a[m].get("ci95", {}).get(k),
             err_label="95% CI (top-1 case bootstrap; rates exact Clopper-Pearson)")
        fig.tight_layout()
        fig.savefig(outdir / "a1_methods.png", dpi=130)
        plt.close(fig)
    if "R" in res and "calibration" in res["R"]:
        cal = res["R"]["calibration"]
        fig, ax = plt.subplots(figsize=(5.2, 5.4))
        ax.plot([0, 1], [0, 1], color="#c3c2b7", linewidth=1, linestyle="--", label="perfect calibration")
        for key, lbl, col in (("raw", "raw ACH score", "#eb6834"),
                              ("isotonic", "isotonic map (fit on pre-cutoff cases)", "#2a78d6")):
            rel = cal[key]["reliability"]
            ci = cal[key].get("ece_ci", [float("nan")] * 2)
            xs, ys = [r["confidence"] for r in rel], [r["accuracy"] for r in rel]
            ax.plot(xs, ys, linewidth=2, color=col, zorder=2,
                    label=f"{lbl}: ECE {cal[key]['ece']:.3f} [{ci[0]:.3f}, {ci[1]:.3f}]")
            ax.scatter(xs, ys, s=[14 + 2.5 * r["n"] for r in rel], color=col, edgecolor=surface, linewidth=1.5,
                       zorder=3)
        ax.set_xlabel("stated probability of the top hypothesis")
        ax.set_ylabel("observed accuracy")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1.02)
        ax.set_title(f"Reliability, per-report temporal test (n={cal['n_test']})", fontsize=9.5, color=ink, loc="left")
        ax.spines[["top", "right"]].set_visible(False)
        ax.legend(frameon=False, fontsize=7, loc="upper left", bbox_to_anchor=(0, -0.13))
        ax.annotate("marker area grows with the cases in the bin; ECE CIs: group-cluster bootstrap",
                    xy=(0, 0), xycoords="axes fraction", xytext=(0, -78), textcoords="offset points",
                    fontsize=6.5, color=muted)
        fig.tight_layout()
        fig.savefig(outdir / "reliability.png", dpi=130)
        plt.close(fig)
    if "D" in res and "level1_seeds" in res["D"]:
        d = res["D"]
        ms = [m for m in ("dragnet", "dragnet-no-ff", "ioc-correlation", "code-only") if m in d["level1_seeds"]]
        e = d.get("level2_ff_effect", {})
        eci = e.get("ci95_case_cluster", [float("nan")] * 2)
        fig, ax = plt.subplots(figsize=(8, 4.3))
        bars(ax, ["level1", "level2"], ["L1: planted Rich header + language", "L2: L1 + stolen exclusive decoy family"],
             ms, lambda lv, m: d[f"{lv}_seeds"][m]["mean"],
             (f"False-flag stress test: share confidently attributed to the decoy (mean of {len(d['seeds'])} decoy "
              f"seeds; lower is better)\nL2 effect of the rules (no-ff minus full engine): "
              f"{e.get('mean_reduction', float('nan')):.2f} [{eci[0]:.2f}, {eci[1]:.2f}], bootstrap clustered by case"),
             err=lambda lv, m: (d[f"{lv}_seeds"][m]["min"], d[f"{lv}_seeds"][m]["max"]),
             err_label="min-max over the decoy seeds (a range, not a CI)")
        fig.tight_layout()
        fig.savefig(outdir / "false_flag.png", dpi=130)
        plt.close(fig)
    if "R" in res:
        rows = {s["method"]: s for s in res["R"]["kfold"]}
        ms = [m for m in ("dragnet", "code-only", "ttp-cosine", "dragnet-no-ttpsim", "dragnet-no-spec",
                          "dragnet-software-only") if m in rows]
        fig, ax = plt.subplots(figsize=(8.4, 4.4))
        bars(ax, ["top1", "coverage", "selective_accuracy"], ["top-1", "coverage", "selective accuracy"], ms,
             lambda k, m: rows[m][k],
             f"Per-report ATT&CK cases, 5-fold leave-report-out (R-kfold, n={rows['dragnet']['n']}): ablations",
             err=lambda k, m: rows[m].get("ci95", {}).get(k),
             err_label="95% CI (top-1 group-cluster bootstrap; rates exact Clopper-Pearson)")
        fig.tight_layout()
        fig.savefig(outdir / "signal_contribution.png", dpi=130)
        plt.close(fig)


# ======================================================================== markdown
def table(summaries: list[dict], cols: list[tuple[str, str]]) -> list[str]:
    out = ["| method | " + " | ".join(h for h, _ in cols) + " |", "|---" * (len(cols) + 1) + "|"]
    for s in summaries:
        out.append(f"| {s['method']} | " + " | ".join(fmt(s.get(k, float("nan"))) for _, k in cols) + " |")
    return out


HEAD_COLS = [("n", "n"), ("top-1", "top1"), ("coverage", "coverage"), ("selective acc.", "selective_accuracy"),
             ("wrong actor named (any grade)", "wrong_any_grade"),
             ("wrong at MEDIUM+ / committed", "confident_error_rate"),
             ("wrong if ties broken at random", "confident_error_expect")]
RANK_COLS = [("in KG", "n_in_kg"), ("top-3", "top3"), ("top-5", "top5"), ("MRR", "mrr"),
             ("Brier (top-1)", "brier"), ("ECE", "ece"), ("Brier (dist.)", "brier_dist")]


def ci_lines(summaries: list[dict], label: str) -> list[str]:
    keys = [("top-1", "top1"), ("coverage", "coverage"), ("selective acc.", "selective_accuracy"),
            ("wrong (any grade)", "wrong_any_grade"), ("wrong at MEDIUM+ / committed", "confident_error_rate")]
    kind = summaries[0].get("top1_ci_kind", "case bootstrap") if summaries else ""
    out = [f"95% intervals ({label}): top-1 by {kind}; proportions exact Clopper-Pearson.", "",
           "| method | " + " | ".join(h for h, _ in keys) + " |", "|---" * (len(keys) + 1) + "|"]
    for s in summaries:
        ci = s.get("ci95", {})
        out.append(f"| {s['method']} | " + " | ".join(
            f"{fmt(s[k])} [{fmt(ci[k][0])}, {fmt(ci[k][1])}]" if k in ci else fmt(s[k]) for _, k in keys) + " |")
    return out + [""]


def fmt_p(p) -> str:
    """p-values: three decimals down to 0.001, then two significant figures (5.0e-06); never 0.000."""
    if p is None or (isinstance(p, float) and math.isnan(p)):
        return "n/a"
    return f"{p:.3f}" if p >= 0.001 else f"{p:.1e}"


def _p_label(v: dict) -> str:
    return "exact" if v.get("exact", True) else f"MC, B = {v.get('n_mc') or P.N_MC:,}"


P_CAPTION = (f"Sign-flip test (one-sided, DRAGNET better): exact when at most 20 discordant units, otherwise "
             f"Monte Carlo with B = {P.N_MC:,} sign flips, p = (k+1)/(B+1); Holm-adjusted across methods.")


def paired_lines(pd: dict, label: str) -> list[str]:
    clustered = any("n_clusters" in v for v in pd.values())
    if not clustered:
        out = [f"Paired top-1 difference, DRAGNET minus method ({label}): case bootstrap 95% CI. {P_CAPTION}", "",
               "| method | diff | 95% CI | discordant cases | p (one-sided) | p (Holm) | p (two-sided) |",
               "|---|---|---|---|---|---|---|"]
        out += [f"| {m} | {fmt(v['diff'])} | [{fmt(v['ci'][0])}, {fmt(v['ci'][1])}] | {v['n_discordant']} | "
                f"{fmt_p(v['p_one_sided'])} ({_p_label(v)}) | {fmt_p(v['p_holm'])} | {fmt_p(v['p_two_sided'])} |"
                for m, v in pd.items()]
        return out + [""]
    out = [(f"Paired top-1 difference, DRAGNET minus method ({label}), clustered by threat group like the marginal "
            f"CIs: group-cluster bootstrap 95% CI; the sign-flip test flips whole groups (per-group summed "
            f"differences). {P_CAPTION} The last column is the case-level test (cases treated as independent), "
            "kept for reference."), "",
           ("| method | diff | 95% CI (group cluster) | discordant cases / groups | p (one-sided) | p (Holm) | "
            "p (two-sided) | case-level p (Holm) |"),
           "|---|---|---|---|---|---|---|---|"]
    for m, v in pd.items():
        cl = v["case_level"]
        out.append(f"| {m} | {fmt(v['diff'])} | [{fmt(v['ci'][0])}, {fmt(v['ci'][1])}] | {v['n_discordant']} / "
                   f"{v['n_discordant_clusters']} | {fmt_p(v['p_one_sided'])} ({_p_label(v)}) | {fmt_p(v['p_holm'])} | "
                   f"{fmt_p(v['p_two_sided'])} | {fmt_p(cl['p_one_sided'])} ({fmt_p(cl['p_holm'])}) |")
    return out + [""]


def grade_lines(g: dict, label: str) -> list[str]:
    out = [f"DRAGNET verdicts by stated grade ({label}), exact 95% CI:", "", "| grade | n named | correct | accuracy [95% CI] |",
           "|---|---|---|---|"]
    out += [f"| {k} | {v['n']} | {v['correct']} | {fmt(v['accuracy'])} [{fmt(v['ci95'][0])}, {fmt(v['ci95'][1])}] |"
            for k, v in g.items()]
    return out + [""]


def rc_lines(summaries: list[dict], label: str) -> list[str]:
    out = [(f"Selective risk (error rate among the most confident cases) at fixed coverage, {label}; "
           "ties in confidence resolved in expectation. Lower is better."), "",
           "| method | risk @20% | risk @40% | risk @60% | risk @100% | AURC |", "|---|---|---|---|---|---|"]
    for s in summaries:
        rc = s.get("risk_coverage")
        if rc:
            r = rc["risk_at"]
            out.append(f"| {s['method']} | {fmt(r['0.2'])} | {fmt(r['0.4'])} | {fmt(r['0.6'])} | {fmt(r['1.0'])} | {fmt(rc['aurc'])} |")
    return out + [""]


def section(res, key, lines):
    return lines if key in res else []


def render_md(res: dict) -> str:
    L = ["# DRAGNET benchmark results", "", "_Generated by `python scripts/run_benchmarks.py`; do not edit by hand._", ""]
    pv = res.get("provenance") or {}
    if pv.get("run_url"):
        L += [(f"Source: bench run [{pv['run_id']}]({pv['run_url']}) on commit "
               f"[`{pv['sha'][:7]}`]({pv['server']}/{pv['repository']}/commit/{pv['sha']}) "
               f"({pv.get('started_utc', '')[:10]}, Python {pv.get('python', '')}, PYTHONHASHSEED={pv.get('hashseed')})."), ""]
    else:
        L += [f"Source: local run ({pv.get('started_utc', 'n/a')[:10]}), not a GitHub Actions bench run.", ""]
    if "kg" in res:
        k = res["kg"]
        L += [(f"Knowledge graph: MITRE ATT&CK Enterprise v{k['attack_version']} - {k['actors']} groups, "
               f"{k['signal_keys']} distinct signal keys, {k['actors_with_country']} groups with a MISP "
               "sponsor-state mapping."), ""]
    L += [("Conventions. A baseline *commits* to an actor only when that actor is its unique top score "
          "(a tie at the top is an abstention); 'wrong if ties broken at random' scores the alternative "
          "convention in expectation. DRAGNET commits at MEDIUM or HIGH; 'wrong actor named (any grade)' "
          "also counts its LOW verdicts. Ranking metrics score ties in expectation."), ""]
    for key in ORDER:
        if key in res:
            L += RENDER[key](res[key]) + [""]
    L += [f"Runtime of the last run: {res.get('runtime_seconds', 'n/a')} s ({res.get('sections_run', '')})", ""]
    return "\n".join(L)


def md_A1LF(r):
    L = ["## A1-LF - ATT&CK campaigns, leave-report-out profiles (controlled campaign set)", "",
         (f"Before each campaign is attributed, every group 'uses' edge whose citations are a subset of the "
          f"campaign's own citations is removed (mean {fmt(r['edges_removed_mean'])} edges per case). This prevents profiles written from the campaign's own reports from answering the question."), ""]
    L += table(r["main"], HEAD_COLS) + [""] + ci_lines(r["main"], "A1-LF") + paired_lines(r["paired"], "A1-LF")
    L += grade_lines(r["grades"], "A1-LF") + rc_lines(r["main"], "A1-LF")
    L += ["### Ablations (A1-LF)", ""] + table(r["ablation"], HEAD_COLS) + [""]
    L += ["Ranking and calibration (A1-LF):", ""] + table(r["main"], RANK_COLS)
    return L


def md_A1(r):
    lk = r["leak"]
    L = ["## A1 - ATT&CK campaigns vs v19.2 group profiles (retrospective, leaky upper bound)", "",
         (f"In {lk['cases_with_own_software_in_true_profile']} of {lk['n']} campaigns the true group's profile "
          f"already lists at least one of the campaign's own software; {lk['dragnet_correct_named_among_them']} "
          f"of DRAGNET's {lk['dragnet_correct_named']} correct named verdicts are among them. Read A1 as an "
          "upper bound; A1-LF is the controlled version."), ""]
    L += table(r["main"], HEAD_COLS) + [""] + ci_lines(r["main"], "A1") + paired_lines(r["paired"], "A1")
    L += grade_lines(r["grades"], "A1") + ["### Ablations (A1)", ""] + table(r["ablation"], HEAD_COLS) + [""]
    L += ["Ranking and calibration (A1):", ""] + table(r["main"], RANK_COLS)
    return L


def md_A2(r):
    L = [f"## A2 - stale profiles: v19.2 campaigns vs ATT&CK v{r['kg_version']} ({r['kg_released'][:10]}) group profiles", "",
         ("ATT&CK v10.1 has no campaign objects, so this is not a temporal hold-out of campaigns: it measures "
          "attribution against older, thinner profiles in an open world (groups added after v10.1 are unknown "
          f"to the graph). The 'later' rows restrict to the {r['n_later']} campaigns whose recorded activity "
          "(first_seen) began after the v10.1 release."), ""]
    L += table(r["main"], HEAD_COLS + [("out-of-KG abstain", "out_of_kg_abstain")]) + [""] + ci_lines(r["main"], "A2")
    g = r["main"][0].get("grades")
    if g:
        L += grade_lines(g, "A2")
    if r["later"]:
        L += [f"### A2-later (activity began after v{r['kg_version']})", ""]
        L += table(r["later"], HEAD_COLS + [("out-of-KG abstain", "out_of_kg_abstain")]) + [""] + ci_lines(r["later"], "A2-later")
    return L


def md_A3(r):
    return (["## A3 - novel malware family attributed from its documented techniques only", ""]
            + table(r["main"], HEAD_COLS) + [""] + ci_lines(r["main"], "A3, top-1 clustered by group")
            + grade_lines(r["grades"], "A3"))


def rcdiff_lines(d: dict, label: str) -> list[str]:
    out = [(f"Selective-risk differences, DRAGNET minus method ({label}); group-cluster bootstrap 95% CIs "
            "(1,000 resamples). Negative = DRAGNET has the lower risk."), "",
           "| method | risk @20% diff [95% CI] | AURC diff [95% CI] |", "|---|---|---|"]
    out += [f"| {m} | {fmt(v['risk20_diff'])} [{fmt(v['risk20_ci'][0])}, {fmt(v['risk20_ci'][1])}] | "
            f"{fmt(v['aurc_diff'])} [{fmt(v['aurc_ci'][0])}, {fmt(v['aurc_ci'][1])}] |" for m, v in d.items()]
    return out + [""]


def md_R(r):
    dt = r.get("dating", {})
    L = ["## R - per-report ATT&CK cases (group x cited report)", "",
         (f"{r['n_cases']} cases over {r['n_groups']} groups: the techniques and software one cited report "
          f"documents for one group (at least 3 techniques). Labels are ATT&CK's own attribution. "
          f"**k-fold**: {r['k']} folds by report; each fold's reports are removed from the profiles before "
          f"its cases are attributed. **Temporal**: every citation dated {r['cutoff_year']} or later is removed "
          f"from the profiles, and the {r['n_temporal']} cases from reports dated {r['cutoff_year']} or later are "
          "attributed. Top-1 CIs are clustered by group."), ""]
    if dt:
        L += [(f"Citation dating: of {dt['citations_on_uses_edges']} citations on 'uses' edges, "
               f"{dt['dated_by_description']} are dated from their reference description '(YYYY, Month DD)', "
               f"{dt['dated_by_key_only']} only from a year in the citation key, and {dt['undated']} have no "
               f"recoverable date ('n.d.'). {dt['key_without_year_dated_later']} citations whose key has no year are "
               f"dated {r['cutoff_year']}+ by their description and held out (an earlier version dated by key only and "
               f"kept them in the profiles); {dt['key_year_disagrees']} keys carry a year that differs from the "
               f"description. Held out: {dt['held_out_later']} citations ({dt['held_out_with_undated']} when undated "
               "citations are also held out, the sensitivity rows below)."), ""]
    L += [f"### R-kfold (n={r['n_cases']})", ""]
    L += table(r["kfold"], HEAD_COLS) + [""] + ci_lines(r["kfold"], "R-kfold") + paired_lines(r["kfold_paired"], "R-kfold")
    L += grade_lines(r["kfold_grades"], "R-kfold") + rc_lines(r["kfold"], "R-kfold")
    if "kfold_rc_diff" in r:
        L += rcdiff_lines(r["kfold_rc_diff"], "R-kfold")
    L += [f"### R-temporal (n={r['n_temporal']})", ""] + table(r["temporal"], HEAD_COLS) + [""]
    L += ci_lines(r["temporal"], "R-temporal") + paired_lines(r["temporal_paired"], "R-temporal")
    L += grade_lines(r["temporal_grades"], "R-temporal") + rc_lines(r["temporal"], "R-temporal")
    if "temporal_rc_diff" in r:
        L += rcdiff_lines(r["temporal_rc_diff"], "R-temporal")
    if "temporal_undated_later" in r:
        L += [f"### R-temporal sensitivity: undated citations also held out (n={r['n_temporal']})", ""]
        L += table(r["temporal_undated_later"], HEAD_COLS) + [""]
        L += ci_lines(r["temporal_undated_later"], "R-temporal, undated held out")
        L += paired_lines(r["temporal_undated_later_paired"], "R-temporal, undated held out")
        L += grade_lines(r["temporal_undated_later_grades"], "R-temporal, undated held out")
    c = r["calibration"]
    bci = c.get("baselines_ece_ci", {})
    L += ["### Calibration of the top-hypothesis probability", "",
          (f"Isotonic map fitted on {c['n_fit']} k-fold cases dated before {r['cutoff_year']}, evaluated on the "
           f"{c['n_test']} temporal test cases (CIs: group-cluster bootstrap, 1,000 resamples)."), "",
          "| forecast | ECE [95% CI] | Brier [95% CI] |", "|---|---|---|",
          (f"| DRAGNET raw ACH score | {fmt(c['raw']['ece'])} [{fmt(c['raw']['ece_ci'][0])}, {fmt(c['raw']['ece_ci'][1])}] | "
          f"{fmt(c['raw']['brier'])} [{fmt(c['raw']['brier_ci'][0])}, {fmt(c['raw']['brier_ci'][1])}] |"),
          (f"| DRAGNET isotonic | {fmt(c['isotonic']['ece'])} [{fmt(c['isotonic']['ece_ci'][0])}, {fmt(c['isotonic']['ece_ci'][1])}] | "
          f"{fmt(c['isotonic']['brier'])} [{fmt(c['isotonic']['brier_ci'][0])}, {fmt(c['isotonic']['brier_ci'][1])}] |")]
    L += [f"| {m} (normalised share, raw) | {fmt(v)}" + (f" [{fmt(bci[m][0])}, {fmt(bci[m][1])}]" if m in bci else "")
          + " | - |" for m, v in c["baselines_ece"].items()]
    return L + [""]


def md_G(r):
    p = r["paper"]
    o = r["ours"]
    L = ["## G - comparison with Guru, Moss & Kochenderfer (2025)", "",
         ("Guru et al. (arXiv:2505.11547) attribute threat reports to 29 actors by scoring "
          "P(technique | actor), estimated from technique counts in training reports, against the techniques "
          "extracted from a test report (machine extraction with text-embedding-3-large over 727 reports); the "
          "metric is the mean rank of the true actor among the 29 (random = 15). Paper protocol: 70/20/10 "
          "split per actor; 10 weight matrices are trained, the best is selected on the validation split and "
          "its test mean rank is reported; the paper does not define its +/-. Their report corpus and "
          "extracted technique counts are not public in reusable form, so the paper's numbers cannot be "
          "reproduced exactly. Our adaptation keeps their scorer, actor set and 70/20/10 split per actor, but "
          "evaluates every one of 10 random splits on its test part (the 20% validation part is unused) and "
          f"uses ATT&CK's human-curated per-report technique lists ({r['n_reports']} reports). Human technique "
          "lists are cleaner than machine extraction, so the adaptation is an optimistic upper bound for their "
          "pipeline. DRAGNET and the other methods use graphs from which every validation/test report has been "
          "removed."), "",
          "| setting | mean rank of true actor (of 29) | 95% CI (pooled, actor cluster) | top-1 |", "|---|---|---|---|",
          f"| paper: random | {p['random']} | - | - |",
          f"| paper: uniform prior | {p['uniform prior'][0]} +/- {p['uniform prior'][1]} | - | - |",
          f"| paper: expert prior | {p['expert prior'][0]} +/- {p['expert prior'][1]} | - | - |",
          f"| paper: HyDE + expert prior (best) | {p['HyDE + expert prior'][0]} +/- {p['HyDE + expert prior'][1]} | - | - |",
          f"| paper artefact: released single test run | {p['released single test (143 docs)']} | - | - |"]
    label = {"guru-uniform": "ours: their scorer, uniform prior (ATT&CK technique lists)",
             "guru-report-prior": "ours: their scorer, prior = training-report share (expert-prior proxy)",
             "ttp-binary-bayes": "ours: ttp-binary-bayes (simplified)", "ttp-jaccard": "ours: ttp-jaccard",
             "dragnet-ttp-only": "ours: DRAGNET, techniques only (= ttp-cosine ranking)",
             "dragnet-software-only": "ours: DRAGNET, software only",
             "dragnet": "ours: DRAGNET (techniques + software)"}
    for m, v in o.items():
        ci = v.get("ci95_actor_cluster")
        L.append(f"| {label.get(m, m)} | {fmt(v['mean_rank'])} +/- {fmt(v['sd'])} | "
                 + (f"[{fmt(ci[0])}, {fmt(ci[1])}]" if ci else "-") + f" | {fmt(v['top1'])} |")
    L += ["", (f"Ours: mean +/- SD over the {r['seeds']} random splits. The 95% CI pools the {r.get('n_pooled', '')} "
               "(split, test report) rows and resamples whole actors, so it reflects actor-level variation; the "
               "splits reuse the same reports and are not independent samples."), ""]
    pv = r.get("paired_vs_dragnet")
    if pv:
        L += [(f"Paired rank difference, method minus DRAGNET (positive = DRAGNET ranks the true actor higher), pooled "
               f"rows, actor-cluster bootstrap CI; sign-flip over per-actor summed differences. {P_CAPTION}"), "",
              "| method | rank diff | 95% CI | splits where DRAGNET is lower | p (one-sided) | p (Holm) |",
              "|---|---|---|---|---|---|"]
        L += [f"| {m} | {fmt(v['rank_diff'])} | [{fmt(v['ci'][0])}, {fmt(v['ci'][1])}] | "
              f"{v['splits_dragnet_better']}/{r['seeds']} | {fmt_p(v['p_one_sided'])} ({_p_label(v)}) | {fmt_p(v['p_holm'])} |"
              for m, v in pv.items()] + [""]
    return L


def md_B(r):
    L = ["## B - larger case sets", "",
         "### B1 - every attributed ATT&CK campaign across releases and domains", "",
         "Attributed campaigns per release: " + ", ".join(f"v{k}: {v}" for k, v in r["attributed_per_release"].items()) + ".",
         (f"The union over releases 12.1-19.2 and the Enterprise, ICS and Mobile domains has {r['union_campaigns']} "
          f"attributed campaigns, {r['B1_cases']} with evidence; new relative to A1: {', '.join(r['B1_new_case_ids']) or 'none'}. "
          "Campaigns are rarely removed from ATT&CK, so the union barely enlarges the set; the per-report cases "
          "(section R) are the real enlargement."), "", "Leave-report-out, Enterprise+ICS+Mobile v19.2 graph:", ""]
    L += table(r["B1"], HEAD_COLS) + [""] + ci_lines(r["B1"], "B1")
    if r.get("B1_paired"):
        L += paired_lines(r["B1_paired"], "B1")
    L += ["### B2 - rolling origin: each campaign vs the newest release published before it was added", "",
          "Release used: " + ", ".join(f"v{k}: {v}" for k, v in sorted(r["B2_release_used"].items())) + ".", ""]
    if r["B2"]:
        L += table(r["B2"], HEAD_COLS + [("out-of-KG abstain", "out_of_kg_abstain")]) + [""] + ci_lines(r["B2"], "B2")
        if r.get("B2_paired"):
            L += paired_lines(r["B2_paired"], "B2")
    else:
        L += ["(no case)"]
    if "B3" in r:
        b = r["B3"]
        L += ["### B3 - Malpedia-labelled abuse.ch cases", "",
              (f"One case per Malpedia family with a single attributed actor and post-{b['cutoff']} abuse.ch "
               f"metadata: up to 20 ThreatFox IOCs and 10 MalwareBazaar samples (imphash, TLSH), sampled with "
               f"{b['seeds']} seeds (means shown). Graph: {b['graph']}; labels come from Malpedia, a source the "
               f"graph does not use. Label agreement Malpedia vs ATT&CK on families both attribute: "
               f"{b['label_agreement']['agree']}/{b['label_agreement']['families_in_both']}."), ""]
        for variant, v in b["variants"].items():
            L += [f"**{variant}** ({v['n_cases']} cases, {v['n_labelled_in_graph']} with the actor in the graph):", "",
                  "| method | top-1 | coverage | selective acc. | wrong (any grade) | wrong at MEDIUM+ / committed | out-of-KG abstain |",
                  "|---|---|---|---|---|---|---|"]
            L += [f"| {m} | {fmt(x['top1'])} | {fmt(x['coverage'])} | {fmt(x['selective_accuracy'])} | "
                  f"{fmt(x['wrong_any_grade'])} | {fmt(x['confident_error_rate'])} | {fmt(x['out_of_kg_abstain'])} |"
                  for m, x in v["per_method"].items()] + [""]
            ci0 = v.get("seed0_ci", {})
            if ci0:
                keys = [("top-1", "top1"), ("coverage", "coverage"), ("selective acc.", "selective_accuracy"),
                        ("wrong (any grade)", "wrong_any_grade")]
                L += [(f"95% CIs for the seed-0 sample of this variant ({variant}): top-1 by case bootstrap, "
                       "proportions exact Clopper-Pearson (the table above shows the 5-seed means)."), "",
                      "| method | " + " | ".join(h for h, _ in keys) + " |", "|---" * (len(keys) + 1) + "|"]
                L += [f"| {m} | " + " | ".join(f"[{fmt(c[k][0])}, {fmt(c[k][1])}]" if k in c else "-" for _, k in keys)
                      + " |" for m, c in ci0.items()] + [""]
    return L


def md_C(r):
    L = ["## C - curated real cases (demonstrations, not validation)", "",
         ("Rules R2 and R4 were designed from the Olympic Destroyer and Turla/OilRig patterns, and several cases "
          "depend on hand-written graph additions (e.g. WannaCry's code-reuse token), so these are "
          "demonstrations that the rules behave as designed, not independent evidence."), ""]
    for mode, rows in r.items():
        L += [f"### {mode}", "", "| case | truth | DRAGNET verdict | truth rank | false-flag indicators | as designed | ioc-correlation | ttp-jaccard |",
              "|---|---|---|---|---|---|---|---|"]
        for x in rows:
            L.append(f"| {x['case']} | {', '.join(x['truth']) or '(none)'} | {x['leading'] or '-'} ({x['confidence']}) | "
                     f"{x['truth_rank'] or '-'} | {len(x['flags'])} | {'yes' if x['behaved_as_expected'] else 'NO'} | "
                     f"{x['baselines']['ioc-correlation'] or '-'} | {x['baselines']['ttp-jaccard'] or '-'} |")
        L += ["", f"Behaved as designed: {sum(x['behaved_as_expected'] for x in rows)}/{len(rows)}", ""]
    return L


def md_D(r):
    L = ["## D - false-flag stress test (planted decoy artifacts on A1 cases)", "",
         ("Decoys are drawn only from other sponsor states (the condition rules R3/R4 check), and the planted "
          "Rich header matches exactly one actor's simulated reference sample, so rule R1 fires by construction "
          "at level 1. Level 2 (a stolen exclusive decoy family) is the informative test."), "",
         (f"False-flag indicators on clean A1 cases (false-alarm rate): {fmt(r['false_alarm_rate_clean'])}"
          + (f" ({round(r['false_alarm_rate_clean'] * r['false_alarm_n'])}/{r['false_alarm_n']}, exact 95% CI "
             f"[{fmt(r['false_alarm_ci'][0])}, {fmt(r['false_alarm_ci'][1])}])" if "false_alarm_ci" in r else "")), ""]
    for lv in ("level1", "level2"):
        ci = r[f"{lv}_dragnet_ci"]
        L += [f"### {lv} (seed 7)", "", "| method | n | decoy ranked #1 | confidently attributed to decoy | truth ranked #1 | flagged | withheld (<=LOW) |",
              "|---|---|---|---|---|---|---|"]
        L += [f"| {x['method']} | {x['n']} | {fmt(x['decoy_top1'])} | {fmt(x['confident_decoy'])} | {fmt(x['truth_top1'])} | "
              f"{fmt(x['flagged'])} | {fmt(x['withheld'])} |" for x in r[lv]]
        L += ["", f"DRAGNET confidently attributed to decoy, exact 95% CI: [{fmt(ci[0])}, {fmt(ci[1])}].", ""]
        sd = r[f"{lv}_seeds"]
        L += [f"Over {len(r['seeds'])} decoy seeds (same cases, different decoys): mean and range (min-max, not a CI):", ""]
        L += [f"- {m}: mean {fmt(v['mean'])}, range {fmt(v['min'])}-{fmt(v['max'])}" for m, v in sd.items()]
        e = r[f"{lv}_ff_effect"]
        L += ["", (f"Effect of the false-flag rules (no-ff minus full engine, confident decoy rate, all case x seed cells): "
              f"{fmt(e['mean_reduction'])}, 95% CI [{fmt(e['ci95_case_cluster'][0])}, {fmt(e['ci95_case_cluster'][1])}] "
              "(bootstrap clustered by case)."), ""]
    return L


def md_E1(r):
    return ["## E1 - ThreatFox export structure and IOC re-sighting", "",
            (f"The export has {r['rows']} rows and {r['distinct_values']} distinct IOC values; "
             f"{fmt(r['share_values_in_one_row'])} of values occur in exactly one row, because ThreatFox records an "
             "IOC once (re-sightings do not create rows). The export therefore cannot measure IOC longevity, and "
             "no longevity conclusion is drawn."), "",
            (f"Actor-specific-family IOCs: {r['actor_family_iocs']} (types: {r['ioc_types']}); network IOCs "
             f"(IP, domain): {r['network_iocs']}, spanning {r['network_span']}. Split at the median network-IOC date "
             f"({r['network_cutoff'][:10]}), {r['network_after_seen_before']} of {r['network_after']} later network "
             "IOCs had an earlier row. Families are mostly commodity: "
             + ", ".join(f"{f} {n}" for f, n in r["top_families"][:6]) + "."), ""]


def _fs(x):
    return (f"{fmt(x['coverage'])} | {fmt(x['selective_accuracy'])} [{fmt(x['ci95_family_cluster'][0])}, "
            f"{fmt(x['ci95_family_cluster'][1])}] | {fmt(x['macro_family_accuracy'])} | {x['families_covered']} | "
            f"{x['distinct_clusters_covered']}")


def md_E2(r):
    L = ["## E2 - MalwareBazaar imphash genetics (train < cutoff, test >= cutoff)", "",
         (f"{r['rows_with_imphash_and_label']} labelled samples with imphash; {r['apt_family_samples']} in actor-specific "
          f"ATT&CK families (train {r['train']}, test {r['test']}). The test samples share only "
          f"{r['test_distinct_imphash']} distinct imphashes and are dominated by a few families ("
          + ", ".join(f"{f} {n}" for f, n in r["test_families"][:5]) + "), so per-sample accuracy mostly measures "
          "re-identification of a few commodity families. CIs resample whole families."), "",
         "| variant | method | coverage | selective acc. [family-cluster 95% CI] | macro acc. over families | families covered | imphashes covered |",
         "|---|---|---|---|---|---|---|"]
    for v in ("collision-filtered", "unfiltered"):
        x = r[v]
        for lbl, k in (("DRAGNET (any grade)", "dragnet"), ("DRAGNET MEDIUM+", "dragnet_medium_plus"),
                       ("imphash lookup", "lookup"), ("DRAGNET, WannaCry excluded", "dragnet_excl_wannacry"),
                       ("DRAGNET MEDIUM+, WannaCry excluded", "medium_plus_excl_wannacry")):
            L.append(f"| {v} | {lbl} | {_fs(x[k])} |")
    L += ["", f"Share of collision-filtered MEDIUM+ verdicts that are WannaCry: {fmt(r['collision-filtered']['medium_plus_wannacry_share'])}.", ""]
    return L


def md_E3(r):
    v = r["validation"]
    taus = ", ".join(f"tau {t}: cov {fmt(x['coverage'])}, acc {fmt(x['selective_accuracy'])}" for t, x in v["by_tau"].items())
    L = ["## E3 - MalwareBazaar TLSH genetics (train < cutoff, test >= cutoff)", "",
         (f"Pre-cutoff TLSH digests of actor-specific families become fuzzy graph signals (collision filter: a "
          f"digest whose radius-tau neighbourhood in a {r['collision_index_size']}-digest pre-cutoff sample spans "
          f"more than 2 families is dropped). tau was chosen on a validation window {v['window']} (n={v['n']}) "
          f"by maximising correct minus twice wrong verdicts: chosen tau = {v['chosen_tau']} ("
          f"{taus}). Graph digests: {r['graph_digests']}; test samples: {r['test']}. Searches are exact (numpy); the stdlib "
          f"banded index recovers {fmt(r['band_index_recall']['recall'])} of the {r['band_index_recall']['true_pairs']} "
          f"true neighbour pairs (within the chosen radius tau = {v['chosen_tau']}) of "
          f"{r['band_index_recall']['queries']} test queries. The shipped runtime default TLSH_TAU = {TLSH_TAU} is more "
          f"conservative than the evaluated tau = {v['chosen_tau']}; at distance < 100 Oliver, Cheng & Chen "
          "(CTC 2013, Table II) report about a 6.43% file-pair false-positive rate."), "",
         "| method | coverage | selective acc. [family-cluster 95% CI] | macro acc. over families | families covered | clusters |",
         "|---|---|---|---|---|---|"]
    for lbl, k in (("DRAGNET (any grade)", "dragnet"), ("DRAGNET MEDIUM+", "dragnet_medium_plus"),
                   ("TLSH nearest-neighbour lookup", "nn_lookup"), ("DRAGNET, WannaCry excluded", "dragnet_excl_wannacry")):
        L.append(f"| {lbl} | {_fs(r[k])} |")
    fa = r["false_alarm"]
    L += ["", (f"False alarms on {fa['n_clean']} post-cutoff samples of families with no actor mapping: an actor was named "
          f"for {fmt(fa['named_any'])} of them, at MEDIUM+ for {fmt(fa['named_medium_plus'])}."), ""]
    return L


def md_F(r):
    L = ["## F - accuracy vs public reporting depth (APTnotes, A1 cases)", "",
         ("An association, not a cause: APTnotes is dense for 2010-2018 and nearly empty afterwards, so "
          "'0 reports' partly means 'recently named actor'. Shown with ATT&CK-only aliases and with MISP aliases "
          "merged (which lets e.g. AppleJeus inherit Lazarus reports)."), ""]
    for label in ("ATT&CK aliases only", "ATT&CK + MISP aliases"):
        x = r[label]
        L += [f"**{label}** (Fisher exact p, 0 vs >0 reports: {fmt(x['fisher_p_zero_vs_some'])})", "",
              "| truth actor reporting | n | DRAGNET top-1 |", "|---|---|---|"]
        L += [f"| {k} | {v['n']} | {fmt(v['top1'])} |" for k, v in x["buckets"].items()] + [""]
    return L


def md_K(r):
    return ["## K - APTMalware hashes in MalwareBazaar metadata (Kida & Olukoya 2023)", "",
            (f"APTMalware (overview.csv, {r['overview_rows']} rows) lists {r['distinct_sha256']} distinct SHA-256s; "
             f"{r['in_bazaar']} of them occur among the {r['bazaar_rows']} rows of the MalwareBazaar metadata export "
             "used here (by group: " + (", ".join(f"{g} {n}" for g, n in r["in_bazaar_by_group"].items()) or "none")
             + "). The fuzzy-hash study of Kida & Olukoya (IEEE Access 11:1148-1165, 2023, "
             "doi:10.1109/ACCESS.2022.3233403) needs the binaries, so its results cannot be matched from metadata. "
             "The export changes daily, so this count drifts."), ""]


RENDER = {"A1": md_A1, "A1LF": md_A1LF, "A2": md_A2, "A3": md_A3, "R": md_R, "G": md_G, "B": md_B, "C": md_C,
          "D": md_D, "E1": md_E1, "E2": md_E2, "E3": md_E3, "F": md_F, "K": md_K}
SECTIONS = {"A1": sec_A1, "A1LF": sec_A1LF, "A2": sec_A2, "A3": sec_A3, "R": sec_R, "G": sec_G, "B": sec_B,
            "C": sec_C, "D": sec_D, "E1": sec_E1, "E2": sec_E2, "E3": sec_E3, "F": sec_F, "K": sec_K}
NEEDS = {"E1": ["threatfox-full.json.zip"], "E2": ["bazaar-full.csv.zip"], "E3": ["bazaar-full.csv.zip"],
         "A2": ["enterprise-attack-10.1.json"], "B": ["enterprise-attack-12.1.json"],
         "K": ["aptmalware-overview.csv", "bazaar-full.csv.zip"]}


def provenance(started: datetime) -> dict:
    """Where these numbers come from: the GitHub Actions run and commit when run there."""
    env = os.environ
    pv = {"started_utc": started.isoformat(timespec="seconds"), "python": platform.python_version(),
          "hashseed": env.get("PYTHONHASHSEED"), "platform": platform.platform(terse=True)}
    if env.get("GITHUB_RUN_ID"):
        server = env.get("GITHUB_SERVER_URL", "https://github.com")
        repo = env.get("GITHUB_REPOSITORY", "")
        pv |= {"run_id": env["GITHUB_RUN_ID"], "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
               "sha": env.get("GITHUB_SHA", ""), "ref": env.get("GITHUB_REF", ""), "workflow": env.get("GITHUB_WORKFLOW"),
               "server": server, "repository": repo, "run_url": f"{server}/{repo}/actions/runs/{env['GITHUB_RUN_ID']}"}
    return pv


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="comma-separated sections (default: all whose data is present)")
    ap.add_argument("--no-figures", action="store_true")
    ap.add_argument("--out", default=str(RESULTS), help="results directory (default: results/)")
    ap.add_argument("--fresh", action="store_true", help="do not merge into an existing benchmark.json")
    ap.add_argument("--render-only", action="store_true",
                    help="re-render RESULTS.md (and figures) from <out>/benchmark.json without running anything")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    out = Path(args.out)
    if args.render_only:
        res = json.loads((out / "benchmark.json").read_text(encoding="utf-8"))
        (out / "RESULTS.md").write_text(render_md(res), encoding="utf-8")
        if not args.no_figures:
            figures(res, REPO / "docs" / "figures")
        print(f"re-rendered {out / 'RESULTS.md'}")
        return 0
    d = data_dir()
    print(f"data dir: {d}")
    wanted = args.only.split(",") if args.only else ALL_SECTIONS
    bad = [s for s in wanted if s not in SECTIONS]
    if bad:
        raise SystemExit(f"unknown sections {bad}; choose from {ALL_SECTIONS}")
    out.mkdir(parents=True, exist_ok=True)
    prev = out / "benchmark.json"
    res: dict = json.loads(prev.read_text(encoding="utf-8")) if prev.exists() and not args.fresh else {}
    res = {k: v for k, v in res.items() if k in SECTIONS or k in ("kg", "datasets")}
    started = datetime.now(timezone.utc)
    t0 = time.time()
    cx = Ctx(d)
    res["datasets"] = json.loads((d / "MANIFEST.json").read_text()) if (d / "MANIFEST.json").exists() else {}
    res["kg"] = {"attack_version": cx.attack.version, "actors": len(cx.kg.actors), "campaign_nodes": len(cx.kg.campaigns),
                 "signal_keys": len(cx.kg.index), "actors_with_country": sum(1 for a in cx.kg.actors if cx.kg.country(a))}
    ran = []
    for s in wanted:
        missing = [f for f in NEEDS.get(s, []) if not (d / f).exists()]
        if missing:
            print(f"[skip] {s}: missing {missing}")
            continue
        t = time.time()
        res[s] = SECTIONS[s](cx)
        ran.append(s)
        print(f"[done] {s} in {time.time() - t:.1f} s")
    res["runtime_seconds"] = round(time.time() - t0, 1)
    res["sections_run"] = ",".join(ran)
    res["provenance"] = provenance(started) | {"sections_run": ran,
                                               "sections_merged_from_previous": sorted(k for k in res if k in SECTIONS
                                                                                       and k not in ran)}
    for sec in ("A1", "A1LF"):
        for s in res.get(sec, {}).get("main", []):
            s.pop("rows", None)
    (out / "benchmark.json").write_text(json.dumps(res, indent=1, default=str, allow_nan=True), encoding="utf-8")
    (out / "RESULTS.md").write_text(render_md(res), encoding="utf-8")
    if not args.no_figures:
        figures(res, REPO / "docs" / "figures")
    print(f"wrote {out / 'RESULTS.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
