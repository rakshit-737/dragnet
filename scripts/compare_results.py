"""Check that a fresh benchmark run reproduces the committed deterministic sections.

Sections built only from SHA-256-pinned data (ATT&CK, MISP, APTnotes) must match the committed
results/benchmark.json value for value: every numeric leaf to 1e-9 (absolute or relative), every
string, bool and null exactly, and no key may appear on one side only. Rows that carry a
``method`` (or ``case``) name are matched by that name, not by list position. A deterministic
section with nothing to compare is a failure, not a pass. Sections on the daily abuse.ch exports
and the live Malpedia API (B3, E1, E2, E3, K) drift with upstream data and are only reported.

Usage: python scripts/compare_results.py results/benchmark.json fresh/benchmark.json
Exit status: 0 when every deterministic section matches, 1 otherwise.
"""
from __future__ import annotations

import json
import math
import sys

DETERMINISTIC = ["A1", "A1LF", "A2", "A3", "R", "G", "B", "C", "D", "F"]
LIVE = ["E1", "E2", "E3", "K"]
# subtrees of deterministic sections that depend on live data, and keys that are run metadata
SKIP_PATHS = {"B/B3"}
SKIP_KEYS = {"seconds"}


def _row_name(x: dict) -> str | None:
    for k in ("method", "case"):
        if isinstance(x.get(k), str):
            return f"{k}={x[k]}" + (f",mode={x['mode']}" if isinstance(x.get("mode"), str) else "")
    return None


def flat(x, path: str = "") -> dict[str, object]:
    """Leaves of a JSON tree keyed by path; named rows in lists are keyed by name."""
    out: dict[str, object] = {}
    if path.lstrip("/") in SKIP_PATHS:
        return out
    if isinstance(x, dict):
        for k, v in x.items():
            if k not in SKIP_KEYS:
                out |= flat(v, f"{path}/{k}")
    elif isinstance(x, list):
        names = [_row_name(v) if isinstance(v, dict) else None for v in x]
        keyed = all(names) and len(set(names)) == len(names)
        for i, v in enumerate(x):
            out |= flat(v, f"{path}[{names[i] if keyed else i}]")
    else:
        out[path] = x
    return out


def same(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool) or a is None or b is None or isinstance(a, str) or isinstance(b, str):
        return a == b
    if isinstance(a, int | float) and isinstance(b, int | float):
        if math.isnan(a) or math.isnan(b):
            return math.isnan(a) and math.isnan(b)
        return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9)
    return a == b


def compare_section(name: str, old, new) -> tuple[int, list[tuple[str, object, object]]]:
    a, b = flat(old, name), flat(new, name)
    diffs = [(k, a.get(k, "<absent>"), b.get(k, "<absent>")) for k in sorted(set(a) | set(b))
             if not (k in a and k in b and same(a[k], b[k]))]
    return len(set(a) | set(b)), diffs


def main(old_path: str, new_path: str) -> int:
    with open(old_path, encoding="utf-8") as f:
        old = json.load(f)
    with open(new_path, encoding="utf-8") as f:
        new = json.load(f)
    ran = (new.get("provenance") or {}).get("sections_run") or [s for s in DETERMINISTIC if s in new]
    bad = compared = 0
    for s in DETERMINISTIC:
        if s not in ran:
            print(f"[skip] {s}: not run in the fresh results")
            continue
        if s not in old or s not in new:
            print(f"[FAIL] {s}: missing in {'committed' if s not in old else 'fresh'} results")
            bad += 1
            continue
        n, diffs = compare_section(s, old[s], new[s])
        if n == 0:
            print(f"[FAIL] {s}: 0 values compared")
            bad += 1
            continue
        compared += 1
        print(f"[{'ok' if not diffs else 'DIFF'}] {s}: {n} values compared, {len(diffs)} differ")
        for k, x, y in diffs[:10]:
            print(f"    {k}: committed {x!r} fresh {y!r}")
        bad += bool(diffs)
    for s in LIVE + ["B/B3"]:
        print(f"[info] {s}: depends on live abuse.ch / Malpedia exports, not compared")
    if not compared:
        print("[FAIL] no deterministic section was compared")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
