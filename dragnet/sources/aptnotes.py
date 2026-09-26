"""APTnotes public report index -> per-actor reporting depth.

APTnotes indexes ~700 public APT reports (2006-2024). DRAGNET uses only the index
metadata (title, source, date) to count how many independent public reports mention
each actor. This is shown next to an attribution as corroboration context and used
in the benchmark to test whether attribution quality tracks reporting depth.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Report:
    title: str
    source: str
    date: str
    year: str
    filename: str


def load_aptnotes(path: str | Path) -> list[Report]:
    with Path(path).open(encoding="utf-8", errors="replace", newline="") as f:
        return [Report(r["Title"], r["Source"], r["Date"], r["Year"], r["Filename"])
                for r in csv.DictReader(f)]


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _mentions(tokens: list[str], alias: str) -> bool:
    at = _tokens(alias)
    if not at:
        return False
    joined = "".join(at)
    if len(joined) < 4 and not any(c.isdigit() for c in joined):
        return False  # too ambiguous ("Rocke", ok; "Ke3" no)
    if joined in tokens:
        return True
    n = len(at)
    return any(tokens[i:i + n] == at for i in range(len(tokens) - n + 1))


def report_counts(reports: list[Report], actor_meta: dict[str, dict]) -> dict[str, int]:
    """actor -> number of APTnotes reports whose title/filename mentions a name or alias."""
    toks = [_tokens(r.title) + _tokens(r.filename.replace("_", " ")) for r in reports]
    out = {}
    for actor, meta in actor_meta.items():
        names = [actor, *meta.get("aliases", [])]
        out[actor] = sum(1 for t in toks if any(_mentions(t, n) for n in names))
    return out
