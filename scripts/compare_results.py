"""Check that a fresh benchmark run reproduces the committed deterministic sections.

Sections built only from SHA-256-pinned data (ATT&CK, MISP, APTnotes) must match the committed
results/benchmark.json to 1e-9; sections on the daily abuse.ch exports (B3, E1, E2, E3) drift
with upstream data and are only reported.

Usage: python scripts/compare_results.py results/benchmark.json fresh/benchmark.json
"""
import json
import math
import sys

DETERMINISTIC = ["A1", "A1LF", "A2", "A3", "R", "G", "C", "D", "F"]
KEYS = ("n", "top1", "coverage", "selective_accuracy", "confident_error_rate", "wrong_any_grade")


def flat(sec) -> dict[str, float]:
    out: dict[str, float] = {}

    def walk(x, path):
        if isinstance(x, dict):
            if "method" in x:
                for k in KEYS:
                    if isinstance(x.get(k), int | float):
                        out[f"{path}/{x['method']}/{k}"] = float(x[k])
                return
            for k, v in x.items():
                walk(v, f"{path}/{k}")
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, f"{path}[{i}]")
    walk(sec, "")
    return out


def main(old_path: str, new_path: str) -> int:
    old, new = json.load(open(old_path, encoding="utf-8")), json.load(open(new_path, encoding="utf-8"))
    bad = 0
    for s in DETERMINISTIC:
        if s not in old or s not in new:
            print(f"[skip] {s}: missing in {'committed' if s not in old else 'fresh'} results")
            continue
        a, b = flat(old[s]), flat(new[s])
        diffs = [(k, a[k], b.get(k)) for k in a if not (b.get(k) is not None and
                 (math.isclose(a[k], b[k], abs_tol=1e-9) or (math.isnan(a[k]) and math.isnan(b[k]))))]
        print(f"[{'ok' if not diffs else 'DIFF'}] {s}: {len(a)} values compared, {len(diffs)} differ")
        for k, x, y in diffs[:10]:
            print(f"    {k}: committed {x} fresh {y}")
        bad += bool(diffs)
    for s in ("B", "E1", "E2", "E3"):
        if s in new:
            print(f"[info] {s}: depends on live abuse.ch / Malpedia exports, not compared")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
