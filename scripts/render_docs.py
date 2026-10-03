"""Render README.md and docs/*.md from templates/ and the committed bench results.

Every @@TOKEN@@ in templates/ is filled from committed files only:
  results/benchmark.json  - all metrics and the source run (provenance)
  results/time.txt        - `/usr/bin/time -v` output of that bench run (wall clock, peak RSS)
No value is typed in by hand. An unknown or unresolved token is an error.

Usage:
  python scripts/render_docs.py           # write README.md and docs/ pages
  python scripts/render_docs.py --check   # exit 1 if a rendered file is stale or any @@TOKEN@@ remains
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
RESULTS = ROOT / "results"
TOKEN = re.compile(r"@@([A-Za-z][A-Za-z0-9_-]*)@@")


def f2(x: float) -> str:
    return f"{x:.2f}"


def ci(c, fmt=f2) -> str:
    return f"[{fmt(c[0])}, {fmt(c[1])}]"


def f3(x: float) -> str:
    return f"{x:.3f}"


def bound(p: float) -> str:
    """Smallest conventional threshold the p-value does not exceed (never rounds down)."""
    return next((f"{t:g}" for t in (0.001, 0.01, 0.05) if p <= t), f3(p))


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def pval(p: float) -> str:
    return f"{p:.1e}" if p < 0.001 else f"{p:.3f}"


def parse_time(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    m = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([0-9:.]+)", text)
    r = re.search(r"Maximum resident set size \(kbytes\): (\d+)", text)
    s = re.search(r"Exit status: (\d+)", text)
    if not (m and r and s):
        raise SystemExit(f"{path}: not a complete `/usr/bin/time -v` output")
    if s.group(1) != "0":
        raise SystemExit(f"{path}: benchmark exit status {s.group(1)}")
    secs = 0.0
    for part in m.group(1).split(":"):
        secs = secs * 60 + float(part)
    return {"wall": secs, "rss_kb": int(r.group(1))}


def by_method(rows, name):
    return next(r for r in rows if r["method"] == name)


def g_text(G: dict) -> str:
    o, pr, paper = G["ours"], G["paired_vs_dragnet"], G["paper"]
    dn = o["dragnet"]
    others = [k for k in o if k != "dragnet"]
    best_other = min(others, key=lambda k: o[k]["mean_rank"])
    worst_p = max(pr[k]["p_holm"] for k in pr)
    all_splits = all(pr[k]["splits_dragnet_better"] == G["seeds"] for k in pr)
    pu = pr["guru-uniform"]
    s = (f"On the same splits DRAGNET ranks the true actor at {f2(dn['mean_rank'])} on average "
         f"(95% CI {ci(dn['ci95_actor_cluster'])}, top-1 {f2(dn['top1'])}), lower than every other method "
         f"here (closest: {best_other}, {f2(o[best_other]['mean_rank'])}); paired against their uniform-prior "
         f"scorer the difference is {f2(pu['rank_diff'])} ranks {ci(pu['ci'])}, and every paired test has "
         f"Holm p <= {bound(worst_p)}")
    s += (f", with DRAGNET lower in all {G['seeds']} splits against each method. " if all_splits else ". ")
    gu, gp = o["guru-uniform"]["mean_rank"], o["guru-report-prior"]["mean_rank"]
    lo, hi = paper["expert prior"][0], paper["uniform prior"][0]
    if lo < gu < hi:
        s += (f"Their scorer on human technique lists ({f2(gu)}) lands between the paper's uniform-prior "
              f"({hi}) and expert-prior ({lo}) results; ")
    else:
        s += f"Their scorer on human technique lists scores {f2(gu)} (paper: uniform {hi}, expert {lo}); "
    s += (f"the report-share prior {'does not help' if gp >= gu else 'helps'} ({f2(gp)}). The corpora differ, "
          f"so the comparison with the paper's own numbers is indicative only.")
    return s


def b2_text(B: dict) -> str:
    rows = B["B2"]
    d = by_method(rows, "dragnet")
    c = d["counts"]
    rel = ", ".join(f"{k}: {v}" for k, v in B["B2_release_used"].items())
    others = "; ".join(
        f"{m} top-1 {f2(r['top1'])} {ci(r['ci95']['top1'])}, {plural(r['counts']['confident_wrong'], 'confident error')}"
        for m in ("ioc-correlation", "code-only") for r in [by_method(rows, m)])
    pd = B["B2_paired"]
    sig = any(pd[k]["p_holm"] < 0.05 for k in pd)
    holm = ", ".join(f"{k} {pval(v['p_holm'])}" for k, v in pd.items())
    return (f"{d['n']} campaigns ({rel} per release), {d['n_in_kg']} with their group in that release. "
            f"DRAGNET top-1 on those is {f2(d['top1'])} {ci(d['ci95']['top1'])}; it names an actor in "
            f"{c['named']} cases, {c['named_ok']} correctly, with {c['confident_wrong']} wrong at MEDIUM+ "
            f"and abstains on {f2(d['out_of_kg_abstain'])} of the {d['n_out_of_kg']} out-of-graph campaigns "
            f"({others}). The paired top-1 differences are "
            f"{'significant' if sig else 'not significant'} at this size "
            f"(Holm p {holm}).")


def e2_text(E2: dict) -> str:
    cf = E2["collision-filtered"]
    d, m, x = cf["dragnet"], cf["dragnet_medium_plus"], cf["dragnet_excl_wannacry"]
    fams = ", ".join(f"{n} {k}" for n, k in E2["test_families"][:3])
    return (f"{E2['test']:,} test samples share {E2['test_distinct_imphash']:,} distinct imphashes and are "
            f"dominated by a few commodity families ({fams}). Collision-filtered, DRAGNET covers "
            f"{f3(d['coverage'])} of them with selective accuracy {f3(d['selective_accuracy'])} "
            f"{ci(d['ci95_family_cluster'], f3)} (CI resamples families); MEDIUM+ verdicts are "
            f"{f3(m['selective_accuracy'])} accurate at coverage {f3(m['coverage'])}, but "
            f"{f2(cf['medium_plus_wannacry_share'])} of them are WannaCry. Without WannaCry, coverage falls "
            f"to {f3(x['coverage'])} and accuracy to {f3(x['selective_accuracy'])} {ci(x['ci95_family_cluster'], f3)}: "
            f"mostly re-identification of known families, not attribution of new ones.")


def e3_text(E3: dict) -> str:
    d, nn, x, fa = E3["dragnet"], E3["nn_lookup"], E3["dragnet_excl_wannacry"], E3["false_alarm"]
    mp = E3["dragnet_medium_plus"]
    return (f"tau = {E3['validation']['chosen_tau']} chosen on a pre-cutoff validation window. DRAGNET covers "
            f"{f3(d['coverage'])} of {E3['test']:,} test samples at selective accuracy "
            f"{f3(d['selective_accuracy'])} {ci(d['ci95_family_cluster'], f3)} (TLSH nearest-neighbour lookup: "
            f"coverage {f3(nn['coverage'])}, accuracy {f3(nn['selective_accuracy'])}); without WannaCry accuracy is "
            f"{f3(x['selective_accuracy'])}. Fuzzy-hash matches never reach MEDIUM+ "
            f"(coverage {f2(mp['coverage'])}); on {fa['n_clean']} samples of families with no actor an actor "
            f"is named for {f3(fa['named_any'])} of them.")


def b3_text(B3: dict) -> str:
    v = B3["variants"]
    a, fn = v["artifacts only"], v["artifacts + family name"]
    da, df = a["per_method"]["dragnet"], fn["per_method"]["dragnet"]
    la = B3["label_agreement"]
    return (f"{a['n_cases']} post-{B3['cutoff']} cases ({a['n_labelled_in_graph']} with the actor in the "
            f"graph), labels from Malpedia, a source the graph does not use ({B3['seeds']}-seed means). From "
            f"artifacts alone DRAGNET's top-1 is {f2(da['top1'])} (coverage {f2(da['coverage'])}); adding "
            f"the family name raises it to {f2(df['top1'])} at selective accuracy "
            f"{f2(df['selective_accuracy'])}, so most of what attributes these cases is the family name, not the hashes or IOCs. "
            f"Malpedia and ATT&CK agree on {la['agree']} of {la['families_in_both']} families both attribute.")


def e1_text(E1: dict) -> str:
    return (f"{f3(E1['share_values_in_one_row'])} of {E1['distinct_values']:,} distinct IOC values occur in "
            f"exactly one row: ThreatFox records an IOC once, so the export cannot measure IOC longevity and "
            f"no longevity claim is made. Only {E1['network_after_seen_before']} of {E1['network_after']} "
            f"later network IOCs of actor-specific families had an earlier row.")


def k_text(K: dict) -> str:
    return (f"Only {K['in_bazaar']} of the {K['distinct_sha256']:,} distinct APTMalware SHA-256s appear among "
            f"the {K['bazaar_rows']:,} rows of the MalwareBazaar metadata export, so the fuzzy-hash study of "
            f"Kida & Olukoya (IEEE Access 2023) cannot be matched from metadata; it needs the binaries. The "
            f"export changes daily, so this count drifts.")


def g_cell(o: dict) -> str:
    return f"{f2(o['mean_rank'])} +/- {f2(o['sd'])} | {ci(o['ci95_actor_cluster'])}"


def values() -> dict:
    res = json.loads((RESULTS / "benchmark.json").read_text(encoding="utf-8"), parse_constant=lambda c: math.nan)
    prov = res["provenance"]
    t = parse_time(RESULTS / "time.txt")
    # time.txt is the wrapper around the same run: its wall clock must match the run's own timer.
    if abs(t["wall"] - res["runtime_seconds"]) > max(30.0, 0.05 * res["runtime_seconds"]):
        raise SystemExit(f"results/time.txt ({t['wall']:.0f} s) does not belong to run {prov['run_id']} "
                         f"(runtime_seconds {res['runtime_seconds']:.0f} s)")
    server, repo, sha = prov["server"], prov["repository"], prov["sha"]
    v = {
        "RUN_ID": prov["run_id"],
        "RUN_URL": prov["run_url"],
        "RUN_SHA7": sha[:7],
        "RUN_COMMIT_URL": f"{server}/{repo}/commit/{sha}",
        "RUNTIME": f"{t['wall']:.0f}",
        "RSS": f"{t['rss_kb'] / 1024:.0f} MiB",
        "K_DISTINCT": f"{res['K']['distinct_sha256']:,}",
        "K_FOUND": str(res["K"]["in_bazaar"]),
        "LABEL_AGREE": "{agree} of {families_in_both}".format(**res["B"]["B3"]["label_agreement"]),
        "G_TEXT": g_text(res["G"]),
        "B2_TEXT": b2_text(res["B"]),
        "B3_TEXT": b3_text(res["B"]["B3"]),
        "E1_TEXT": e1_text(res["E1"]),
        "E2_TEXT": e2_text(res["E2"]),
        "E3_TEXT": e3_text(res["E3"]),
        "K_TEXT": k_text(res["K"]),
    }
    for name, o in res["G"]["ours"].items():
        v[f"G_{name}"] = g_cell(o)
    return v


def render(text: str, v: dict, src: Path) -> str:
    missing = sorted({m for m in TOKEN.findall(text) if m not in v})
    if missing:
        raise SystemExit(f"{src}: no data source for token(s) {', '.join(missing)}")
    return TOKEN.sub(lambda m: v[m.group(1)], text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="verify instead of writing")
    args = ap.parse_args()
    v = values()
    stale = []
    for src in sorted(p for p in TEMPLATES.rglob("*.md")):
        dst = ROOT / src.relative_to(TEMPLATES)
        out = render(src.read_text(encoding="utf-8"), v, src)
        cur = dst.read_text(encoding="utf-8") if dst.exists() else None
        if args.check:
            if cur != out:
                stale.append(dst.relative_to(ROOT).as_posix())
        elif cur != out:
            dst.write_text(out, encoding="utf-8", newline="\n")
            print(f"rendered {dst.relative_to(ROOT).as_posix()}")
    # No placeholder may survive anywhere in the published docs, templated or not.
    left = [f"{p.relative_to(ROOT).as_posix()}: @@{m}@@" for p in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
            for m in TOKEN.findall(p.read_text(encoding="utf-8"))]
    for x in left:
        print(f"unresolved token {x}", file=sys.stderr)
    for x in stale:
        print(f"stale: {x} (run python scripts/render_docs.py)", file=sys.stderr)
    return 1 if (left or stale) else 0


if __name__ == "__main__":
    sys.exit(main())
