"""Run every DRAGNET benchmark on the downloaded real data and write results/.

  A1  ATT&CK v19.2 campaigns -> v19.2 group profiles        (retrospective)
  A2  ATT&CK v19.2 campaigns created after v10.1 -> v10.1   (temporal hold-out, open-world)
  C   Curated real case studies (WannaCry, NotPetya, Olympic Destroyer, Turla/OilRig, ...)
      in time-of-incident and retrospective knowledge modes
  D   False-flag stress test: planted decoy artifacts on A1 cases
  E   abuse.ch: MalwareBazaar imphash genetics (temporal) + ThreatFox IOC shelf-life
  F   Does accuracy track public reporting depth (APTnotes)?

Usage: python scripts/run_benchmarks.py [--skip-bazaar] [--no-figures]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from dragnet import bench
from dragnet.ach import EngineConfig, assess
from dragnet.bench import METHODS, fmt
from dragnet.cases import addition_campaigns, load_real_cases
from dragnet.graph import KnowledgeGraph
from dragnet.kg_build import (
    build_from_attack,
    enrich_bazaar,
    family_actor_map,
    imphash_family_index,
)
from dragnet.models import Signal, SignalKind
from dragnet.paths import FIXTURES, RESULTS, data_dir
from dragnet.sources.abusech import iter_bazaar, iter_threatfox
from dragnet.sources.aptnotes import load_aptnotes, report_counts
from dragnet.sources.attack import load_attack
from dragnet.sources.misp import load_malpedia_families, load_threat_actors, norm

MAIN = ["dragnet", "ttp-jaccard", "ttp-cosine", "ioc-correlation", "code-only"]
ABL = ["dragnet", "dragnet-no-spec", "dragnet-no-ttpsim", "dragnet-no-ff"]


def table(summaries: list[dict], cols: list[tuple[str, str]]) -> list[str]:
    out = ["| method | " + " | ".join(h for h, _ in cols) + " |",
           "|---" * (len(cols) + 1) + "|"]
    for s in summaries:
        out.append(f"| {s['method']} | " + " | ".join(fmt(s[k]) for _, k in cols) + " |")
    return out


RANK_COLS = [("n", "n"), ("in KG", "n_in_kg"), ("top-1", "top1"), ("top-3", "top3"), ("top-5", "top5"), ("MRR", "mrr"),
             ("coverage", "coverage"), ("selective acc.", "selective_accuracy"),
             ("confident-error rate", "confident_error_rate"), ("Brier (top-1)", "brier"), ("ECE", "ece"),
             ("Brier (dist.)", "brier_dist")]


def ci_table(summaries: list[dict], label: str) -> list[str]:
    keys = [("top-1", "top1"), ("selective acc.", "selective_accuracy"),
            ("confident-error rate", "confident_error_rate"), ("coverage", "coverage")]
    out = [f"95% bootstrap CIs ({label}, 2000 case resamples):", "",
           "| method | " + " | ".join(h for h, _ in keys) + " |", "|---" * (len(keys) + 1) + "|"]
    for s in summaries:
        ci = s.get("ci95", {})
        out.append(f"| {s['method']} | " + " | ".join(
            f"{fmt(s[k])} [{fmt(ci[k][0])}, {fmt(ci[k][1])}]" if k in ci else fmt(s[k]) for _, k in keys) + " |")
    return out + [""]


def strip_rows(s: dict) -> dict:
    return {k: v for k, v in s.items() if k != "rows"}


def run_curated(attack, misp, malpedia, mode: str, gamma: float = 1.0) -> list[dict]:
    names = {g.attack_id: g.name for g in attack.groups.values()}
    out = []
    for case in load_real_cases(FIXTURES / "real_cases", attack):
        hide = set(case.novel_software) if mode == "time-of-incident" else set()
        base = build_from_attack(attack, misp=misp, malpedia=malpedia, exclude_software=hide)
        kg = KnowledgeGraph(list(base.campaigns.values()) + addition_campaigns(case, attack),
                            base.actor_meta, base.meta)
        a = assess(case.case_id, case.signals, kg, config=EngineConfig(posterior_gamma=gamma))
        truth = {names[g] for g in case.ground_truth if g in names}
        ranked = a.ranked_actors
        rank = next((i + 1 for i, x in enumerate(ranked) if x in truth), None)
        p_truth = max((a.posterior.get(t, 0.0) for t in truth), default=a.posterior.get("UNKNOWN", 0.0))
        if case.expected == "attribute":
            ok = a.leading in truth
        elif case.expected == "withhold":
            # a false flag must be surfaced and no MEDIUM/HIGH verdict issued
            ok = bool(a.false_flag_indicators) and a.confidence.value in ("LOW", "INSUFFICIENT")
        else:
            ok = a.leading is None
        base_preds = {m: METHODS[m](case.signals, kg) for m in ("ttp-jaccard", "ioc-correlation", "code-only")}
        out.append({
            "case": case.case_id, "title": case.title, "mode": mode, "truth": sorted(truth),
            "false_flag": case.false_flag, "expected": case.expected,
            "leading": a.leading, "confidence": a.confidence.value, "top_ranked": ranked[0] if ranked else None,
            "truth_rank": rank, "p_truth": p_truth,
            "top_score": max((h.score for h in a.hypotheses if h.hypothesis in ranked[:1]), default=0.0), "flags": a.false_flag_indicators, "notes": a.notes,
            "brier": bench._brier(a.posterior, truth), "behaved_as_expected": ok,
            "baselines_top1": {m: p.named for m, p in base_preds.items()},
        })
    return out


def bazaar_benchmark(attack, malpedia, path: Path, cutoff: str) -> dict:
    t0 = time.time()
    fam = family_actor_map(attack, 3, malpedia)
    rows = [s for s in iter_bazaar(path) if s.imphash and s.signature]
    # collision index from the training period only: using post-cutoff samples would leak
    # future knowledge of which imphashes turn out to be shared across families
    gidx = imphash_family_index([s for s in rows if s.first_seen < cutoff])
    apt = [s for s in rows if norm(s.signature) in fam]
    train = [s for s in apt if s.first_seen < cutoff]
    test = [s for s in apt if s.first_seen >= cutoff]
    kg0 = build_from_attack(attack, malpedia=malpedia, language_signals=False)
    res = {"rows_with_imphash_and_label": len(rows), "apt_family_samples": len(apt),
           "train": len(train), "test": len(test), "cutoff": cutoff,
           "apt_families_seen": sorted({s.signature for s in apt})}
    for variant, gi in (("collision-filtered", gidx), ("unfiltered", None)):
        kg, hits = enrich_bazaar(kg0, attack, train, global_index=gi, malpedia=malpedia)
        n = cov = ok = conf = conf_ok = 0
        base_cov = base_ok = 0
        cache: dict[str, tuple] = {}     # samples sharing an imphash get the same verdict
        for s in test:
            truth = fam[norm(s.signature)]
            if s.imphash not in cache:
                sigs = [Signal(SignalKind.IMPHASH, s.imphash, s.sha256)]
                a = assess(s.sha256, sigs, kg)
                cache[s.imphash] = (a.leading, a.confidence.value, METHODS["code-only"](sigs, kg).named)
            leading, grade, base_named = cache[s.imphash]
            n += 1
            if leading:
                cov += 1
                ok += leading in truth
            if grade in ("HIGH", "MEDIUM"):
                conf += 1
                conf_ok += leading in truth
            if base_named:
                base_cov += 1
                base_ok += base_named in truth
        f = lambda a, b: a / b if b else float("nan")
        res[variant] = {"n_test": n, "dragnet_coverage": f(cov, n), "dragnet_selective_acc": f(ok, cov),
                        "dragnet_medium_plus": f(conf, n), "dragnet_medium_plus_acc": f(conf_ok, conf),
                        "lookup_coverage": f(base_cov, n), "lookup_selective_acc": f(base_ok, base_cov),
                        "families_indexed": len(hits)}
    res["seconds"] = round(time.time() - t0, 1)
    return res


def threatfox_shelf_life(attack, malpedia, path: Path) -> dict:
    """Split actor-specific-family IOCs at their median first-seen time and measure how
    many later IOCs were already known: the ceiling for IOC-only attribution over time."""
    fam = family_actor_map(attack, 3, malpedia)
    rows = []
    all_rows = 0
    for i in iter_threatfox(path):
        all_rows += 1
        key = norm(i.malware_printable)
        if key not in fam and norm(i.malware.split(".", 1)[-1]) not in fam:
            continue
        v = i.value.rsplit(":", 1)[0] if i.ioc_type == "ip:port" else i.value
        rows.append((i.first_seen, v, i.malware_printable))
    rows.sort()
    cutoff = rows[len(rows) // 2][0] if rows else ""
    before = {v: f for t, v, f in rows if t < cutoff}
    after = [(v, f) for t, v, f in rows if t >= cutoff]
    reuse = sum(1 for v, _ in after if v in before)
    fams = Counter(f for _, f in after) + Counter(before.values())
    return {"threatfox_rows": all_rows, "families": len({f for _, _, f in rows}), "apt_family_iocs_before": len(before),
            "apt_family_iocs_after": len(after), "cutoff": cutoff,
            "after_seen_before": reuse, "ioc_reuse_rate": reuse / len(after) if after else float("nan"),
            "top_families": fams.most_common(10)}


def figures(res: dict, outdir: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - skipping figures")
        return
    outdir.mkdir(parents=True, exist_ok=True)
    # fixed categorical order (reference palette slots 1-5), never cycled
    colors = {"dragnet": "#2a78d6", "ttp-jaccard": "#eb6834", "ttp-cosine": "#1baf7a",
              "ioc-correlation": "#eda100", "code-only": "#e87ba4"}
    ink, muted = "#0b0b0b", "#52514e"
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": muted, "axes.labelcolor": ink,
                         "xtick.color": muted, "ytick.color": muted})

    # 1) A1 top-1 / top-3 / confident-error rate per method
    a1 = {s["method"]: s for s in res["A1"]["main"]}
    metrics = [("top1", "top-1"), ("top3", "top-3"), ("confident_error_rate", "confident error")]
    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    width = 0.16
    for i, m in enumerate(MAIN):
        xs = [j + (i - 2) * width for j in range(len(metrics))]
        vals = [a1[m][k] for k, _ in metrics]
        bars = ax.bar(xs, vals, width - 0.02, color=colors[m], label=m)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v:.2f}", ha="center",
                    va="bottom", fontsize=7, color=ink)
    ax.set_xticks(range(len(metrics)), [lbl for _, lbl in metrics])
    ax.set_ylim(0, 1.05)
    ax.set_title(f"ATT&CK campaigns (n={a1['dragnet']['n']}): ranking vs committed errors",
                 fontsize=10, color=ink, loc="left")
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color="#e4e3df", linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=8, ncol=5, loc="upper center", bbox_to_anchor=(0.5, -0.1))
    fig.tight_layout()
    fig.savefig(outdir / "a1_methods.png", dpi=130)
    plt.close(fig)

    # 2) reliability diagram (A1) dragnet vs ioc-correlation
    fig, ax = plt.subplots(figsize=(4.4, 4.2))
    ax.plot([0, 1], [0, 1], color="#c3c2b7", linewidth=1, linestyle="--", label="perfect calibration")
    series = [("dragnet", "dragnet", "#2a78d6"), ("ioc-correlation", "ioc-correlation", "#eda100")]
    for label, key, col in series:
        rel = next(s for s in res["A1"]["main"] if s["method"] == key)["reliability"]
        ax.plot([r["confidence"] for r in rel], [r["accuracy"] for r in rel], marker="o",
                markersize=5, linewidth=2, color=col, label=label)
    ax.set_xlabel("stated probability of top hypothesis")
    ax.set_ylabel("observed accuracy")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title(f"Reliability of top-1 forecast, A1 (n={res['A1']['main'][0]['n']})", fontsize=10, color=ink, loc="left")
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(outdir / "reliability.png", dpi=130)
    plt.close(fig)

    # 3) false-flag stress: decoy capture rate per method, levels 1 and 2
    fig, ax = plt.subplots(figsize=(7.5, 3.4))
    levels = ["level1", "level2"]
    for i, m in enumerate(MAIN):
        xs = [j + (i - 2) * width for j in range(len(levels))]
        vals = [next(r for r in res["D"][lv] if r["method"] == m)["confident_decoy"] for lv in levels]
        bars = ax.bar(xs, vals, width - 0.02, color=colors[m], label=m)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v:.2f}", ha="center",
                    va="bottom", fontsize=7, color=ink)
    ax.set_xticks(range(2), ["L1: planted Rich header + language", "L2: L1 + stolen decoy family"])
    ax.set_ylim(0, 1.05)
    ax.set_title("False-flag stress test: share of cases confidently attributed to the decoy (lower is better)",
                 fontsize=9, color=ink, loc="left")
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color="#e4e3df", linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=8, ncol=5, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    fig.tight_layout()
    fig.savefig(outdir / "false_flag.png", dpi=130)
    plt.close(fig)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-bazaar", action="store_true")
    ap.add_argument("--no-figures", action="store_true")
    ap.add_argument("--cutoff", default="2024-01-01", help="temporal split for abuse.ch data")
    args = ap.parse_args(argv)
    d = data_dir()
    t0 = time.time()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(f"data dir: {d}")
    attack = load_attack(d / "enterprise-attack-19.2.json")
    misp = load_threat_actors(d / "misp-threat-actor.json")
    malpedia = load_malpedia_families(d / "misp-malpedia.json")
    res: dict = {"datasets": json.loads((d / "MANIFEST.json").read_text()) if (d / "MANIFEST.json").exists() else {}}

    # ---- A1
    kg = build_from_attack(attack, misp=misp, malpedia=malpedia)
    cases = bench.attack_campaign_cases(attack, attack)
    res["kg"] = {"attack_version": attack.version, "actors": len(kg.actors),
                 "campaign_nodes": len(kg.campaigns), "signal_keys": len(kg.index),
                 "actors_with_country": sum(1 for a in kg.actors if kg.country(a))}
    print(f"A1: {len(cases)} ATT&CK campaigns vs {len(kg.actors)} groups")
    # ---- A3 novel-family (behaviour-only) attribution; also the calibration set
    cases3 = bench.novel_family_cases(attack)
    print(f"A3: {len(cases3)} single-group malware families")
    res["A3"] = {"main": [strip_rows(bench.evaluate(m, cases3, kg))
                          for m in ("dragnet", "ttp-jaccard", "ttp-cosine")]}

    allm = list(dict.fromkeys(MAIN + ABL))
    preds = {m: bench.predict_all(m, cases, kg) for m in allm}
    summ = {m: bench.evaluate(m, cases, kg, preds[m]) for m in allm}
    for m in allm:
        summ[m]["ci95"] = bench.bootstrap_ci(summ[m]["rows"])
    res["A1"] = {"main": [summ[m] for m in MAIN],
                 "ablation": [strip_rows(summ[m]) for m in ABL],
                 "paired_top1_vs_dragnet": {m: bench.paired_bootstrap_diff(summ["dragnet"]["rows"], summ[m]["rows"])
                                            for m in allm if m != "dragnet"}}

    # ---- F reporting depth (APTnotes) on A1 rows
    reports = load_aptnotes(d / "APTnotes.csv")
    counts = report_counts(reports, kg.actor_meta)
    rows = summ["dragnet"]["rows"]
    for r in rows:
        r["aptnotes_reports"] = max((counts.get(t, 0) for t in r["truth"]), default=0)
    buckets = {"0 reports": [r for r in rows if r["aptnotes_reports"] == 0],
               "1-5 reports": [r for r in rows if 1 <= r["aptnotes_reports"] <= 5],
               ">5 reports": [r for r in rows if r["aptnotes_reports"] > 5]}
    res["F"] = {"aptnotes_reports_indexed": len(reports),
                "actors_with_reports": sum(1 for v in counts.values() if v),
                "buckets": {k: {"n": len(v), "top1": sum(r["top1"] for r in v) / len(v) if v else float("nan")}
                            for k, v in buckets.items()},
                "top_actors": Counter(counts).most_common(10)}

    # ---- A2 temporal
    p10 = d / "enterprise-attack-10.1.json"
    if p10.exists():
        attack10 = load_attack(p10)
        kg10 = build_from_attack(attack10, misp=misp, malpedia=malpedia)
        cases10 = bench.attack_campaign_cases(attack, attack10, created_after=attack10.released)
        print(f"A2: {len(cases10)} campaigns created after v{attack10.version} ({attack10.released[:10]})")
        res["A2"] = {"kg_version": attack10.version, "kg_released": attack10.released,
                     "main": []}
        for m in MAIN:
            sm = bench.evaluate(m, cases10, kg10)
            sm["ci95"] = bench.bootstrap_ci(sm["rows"])
            res["A2"]["main"].append(strip_rows(sm))

    # ---- D false-flag stress test
    kg_rh = bench.reference_rich_headers(kg)
    res["D"] = {"false_alarm_rate_clean": bench.false_alarm_rate(cases, kg_rh)}
    for level in (1, 2):
        planted = bench.plant_false_flags(cases, kg, level)
        res["D"][f"level{level}"] = [bench.evaluate_false_flag(m, planted, kg_rh)
                                     for m in MAIN + ["dragnet-no-ff"]]
    # decoy choice is random: repeat over seeds and report the spread
    seeds = list(range(10))
    res["D"]["seeds"] = seeds
    for level in (1, 2):
        per = {m: [] for m in MAIN + ["dragnet-no-ff"]}
        for sd in seeds:
            planted = bench.plant_false_flags(cases, kg, level, seed=sd)
            for m, vals in per.items():
                vals.append(bench.evaluate_false_flag(m, planted, kg_rh)["confident_decoy"])
        res["D"][f"level{level}_seeds"] = {m: {"mean": sum(v) / len(v), "min": min(v), "max": max(v)}
                                           for m, v in per.items()}
    print("D: false-flag stress test done")

    # ---- C curated
    res["C"] = {mode: run_curated(attack, misp, malpedia, mode)
                for mode in ("time-of-incident", "retrospective")}

    # ---- E abuse.ch
    tf = d / "threatfox-full.json.zip"
    if tf.exists():
        res["E_threatfox"] = threatfox_shelf_life(attack, malpedia, tf)
    bz = d / "bazaar-full.csv.zip"
    if bz.exists() and not args.skip_bazaar:
        res["E_bazaar"] = bazaar_benchmark(attack, malpedia, bz, args.cutoff)
    res["runtime_seconds"] = round(time.time() - t0, 1)

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "benchmark.json").write_text(json.dumps(res, indent=1, default=str,
                                                       allow_nan=True), encoding="utf-8")
    (RESULTS / "RESULTS.md").write_text(render_md(res), encoding="utf-8")
    if not args.no_figures:
        figures(res, REPO / "docs" / "figures")
    print((RESULTS / "RESULTS.md").read_text(encoding="utf-8"))
    return 0


def render_md(res: dict) -> str:
    L = ["# DRAGNET benchmark results", "",
         "_Generated by `python scripts/run_benchmarks.py`; do not edit by hand._", ""]
    k = res["kg"]
    L += [(f"Knowledge graph: MITRE ATT&CK Enterprise v{k['attack_version']} - {k['actors']} groups, "
           f"{k['signal_keys']} distinct signal keys, {k['actors_with_country']} groups with a MISP "
           f"sponsor-state mapping."), ""]
    L += [("Calibration metrics score the binary forecast 'the top-ranked actor is the culprit': "
           "DRAGNET's stated probability is its ACH score for that actor, a baseline's is its "
           "normalised share. 'Brier (dist.)' scores the full normalised distribution over hypotheses."), ""]
    L += ["## A3 - novel malware family attributed from its documented techniques only", ""]
    L += table(res["A3"]["main"], RANK_COLS) + [""]
    L += ["## A1 - ATT&CK campaigns attributed against group profiles (retrospective)", ""]
    L += table(res["A1"]["main"], RANK_COLS) + [""]
    L += ci_table(res["A1"]["main"], "A1")
    L += ["Paired bootstrap, top-1 difference DRAGNET minus method (same cases, 2000 resamples):", "",
          "| method | diff | 95% CI | P(diff <= 0) |", "|---|---|---|---|"]
    L += [f"| {m} | {fmt(v['diff'])} | [{fmt(v['ci'][0])}, {fmt(v['ci'][1])}] | {fmt(v['p_le_0'])} |"
          for m, v in res["A1"]["paired_top1_vs_dragnet"].items()] + [""]
    g = next(s for s in res["A1"]["main"] if s["method"] == "dragnet")["grades"]
    L += ["DRAGNET accuracy by stated confidence (A1):", "", "| grade | n | accuracy |", "|---|---|---|"]
    L += [f"| {gr} | {v['n']} | {fmt(v['accuracy'])} |" for gr, v in g.items()] + [""]
    L += ["### Ablations (A1)", ""] + table(res["A1"]["ablation"], RANK_COLS) + [""]
    if "A2" in res:
        L += [f"## A2 - temporal hold-out: v{res['A2']['kg_version']} profiles, campaigns documented later", ""]
        L += table(res["A2"]["main"], RANK_COLS + [("out-of-KG abstain", "out_of_kg_abstain")]) + [""]
        L += ci_table(res["A2"]["main"], "A2")
    L += ["## C - curated real cases", ""]
    for mode, rows in res["C"].items():
        L += [f"### {mode}", "", "| case | truth | DRAGNET verdict | top score | truth rank | false-flag indicators | as expected | ioc-correlation | ttp-jaccard |",
              "|---|---|---|---|---|---|---|---|---|"]
        for r in rows:
            verdict = f"{r['leading'] or '-'} ({r['confidence']})"
            L.append(f"| {r['case']} | {', '.join(r['truth']) or '(none)'} | {verdict} | {r['top_score']:.2f} | "
                     f"{r['truth_rank'] or '-'} | {len(r['flags'])} | {'yes' if r['behaved_as_expected'] else 'NO'} | "
                     f"{r['baselines_top1']['ioc-correlation'] or '-'} | {r['baselines_top1']['ttp-jaccard'] or '-'} |")
        n_ok = sum(r["behaved_as_expected"] for r in rows)
        L += ["", f"Behaved as expected: {n_ok}/{len(rows)}", ""]
    D = res["D"]
    L += ["## D - false-flag stress test (planted decoy artifacts on A1 cases)", "",
          f"False-flag indicators raised on clean A1 cases (false-alarm rate): {fmt(D['false_alarm_rate_clean'])}", ""]
    for lv in ("level1", "level2"):
        L += [f"### {lv}", "", "| method | n | decoy ranked #1 | confidently attributed to decoy | truth ranked #1 | flagged | withheld (<=LOW) |",
              "|---|---|---|---|---|---|---|"]
        for r in D[lv]:
            L.append(f"| {r['method']} | {r['n']} | {fmt(r['decoy_top1'])} | {fmt(r['confident_decoy'])} | "
                     f"{fmt(r['truth_top1'])} | {fmt(r['flagged'])} | {fmt(r['withheld'])} |")
        L.append("")
        sd = D.get(f"{lv}_seeds")
        if sd:
            L += [f"Over {len(D['seeds'])} decoy seeds - confidently attributed to decoy, mean [min, max]:", ""]
            L += [f"- {m}: {fmt(v['mean'])} [{fmt(v['min'])}, {fmt(v['max'])}]" for m, v in sd.items()] + [""]
    if "E_threatfox" in res:
        t = res["E_threatfox"]
        L += ["## E1 - ThreatFox IOC shelf-life (actor-specific families)", "",
              (f"{t['apt_family_iocs_before']} IOCs before {t['cutoff']}, {t['apt_family_iocs_after']} after; "
               f"{t['after_seen_before']} of the later IOCs were already known "
               f"(reuse rate {fmt(t['ioc_reuse_rate'])})."), ""]
    if "E_bazaar" in res:
        b = res["E_bazaar"]
        L += ["## E2 - MalwareBazaar imphash genetics (train < cutoff, test >= cutoff)", "",
              (f"{b['rows_with_imphash_and_label']} labelled samples with imphash; "
               f"{b['apt_family_samples']} belong to actor-specific ATT&CK families "
               f"(train {b['train']}, test {b['test']})."), "",
              "| variant | test n | DRAGNET coverage | DRAGNET selective acc. | DRAGNET MEDIUM+ share | MEDIUM+ acc. | lookup coverage | lookup selective acc. |",
              "|---|---|---|---|---|---|---|---|"]
        for v in ("collision-filtered", "unfiltered"):
            x = b[v]
            L.append(f"| {v} | {x['n_test']} | {fmt(x['dragnet_coverage'])} | {fmt(x['dragnet_selective_acc'])} | "
                     f"{fmt(x['dragnet_medium_plus'])} | {fmt(x['dragnet_medium_plus_acc'])} | "
                     f"{fmt(x['lookup_coverage'])} | {fmt(x['lookup_selective_acc'])} |")
        L.append("")
    F = res["F"]
    L += ["## F - accuracy vs public reporting depth (APTnotes)", "", "| truth actor reporting | n | DRAGNET top-1 |", "|---|---|---|"]
    L += [f"| {k} | {v['n']} | {fmt(v['top1'])} |" for k, v in F["buckets"].items()]
    L += ["", f"Runtime: {res['runtime_seconds']} s", ""]
    return "\n".join(L)


if __name__ == "__main__":
    raise SystemExit(main())
