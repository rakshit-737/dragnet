"""Render the bundled synthetic scenarios as static report pages for the docs site (docs/demo/).

Deterministic: custody timestamps are fixed so re-running produces identical pages.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from dragnet.ach import assess
from dragnet.custody import CustodyLog
from dragnet.graph import KnowledgeGraph
from dragnet.ingest import build_case
from dragnet.report import to_markdown
from dragnet.stix import to_stix_json

TS = "2026-01-01T00:00:00+00:00"


class FixedClockLog(CustodyLog):
    def record(self, action, item_id, item_hash, actor="dragnet", ts=None):
        return super().record(action, item_id, item_hash, actor, ts=TS)


def main() -> int:
    out = REPO / "docs" / "demo"
    out.mkdir(parents=True, exist_ok=True)
    kg = KnowledgeGraph.load(REPO / "dragnet" / "data" / "campaigns.json")
    rows = []
    for path in sorted((REPO / "dragnet" / "data" / "cases").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        case_id, _items, signals, custody = build_case(data, FixedClockLog())
        a = assess(case_id, signals, kg, None, custody)
        (out / f"{path.stem}.md").write_text(to_markdown(a), encoding="utf-8")
        (out / f"{path.stem}.stix.json").write_text(to_stix_json(a, "2026-01-01T00:00:00.000Z") + "\n",
                                                   encoding="utf-8")
        rows.append((path.stem, a.leading or "withheld", a.confidence.value, len(a.false_flag_indicators)))
    L = ["# Demo reports", "",
         "Static reports for the synthetic spec scenarios in `dragnet/data/cases/`, assessed against the",
         "synthetic knowledge graph `dragnet/data/campaigns.json` (no downloads needed). Regenerate with",
         "`python scripts/build_demo_pages.py`. Each report also has a STIX 2.1 bundle.", "",
         "| scenario | verdict | confidence | false-flag indicators | STIX |", "|---|---|---|---|---|"]
    L += [f"| [{s}]({s}.md) | {lead} | {conf} | {ff} | [bundle]({s}.stix.json) |" for s, lead, conf, ff in rows]
    L += ["", "Real-data case studies (WannaCry, NotPetya, Olympic Destroyer, ...) need the downloaded",
          "datasets; their results are on the [benchmarks page](../benchmarks.md).", ""]
    (out / "index.md").write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {len(rows)} demo reports to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
