"""DRAGNET command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ach import assess
from .graph import KnowledgeGraph
from .ingest import load_case
from .models import SignalKind
from .report import to_json, to_markdown

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KG = ROOT / "fixtures" / "campaigns.json"
CASES = ROOT / "fixtures" / "cases"


def parse_weights(pairs) -> dict[SignalKind, float]:
    out = {}
    for p in pairs or []:
        k, _, v = p.partition("=")
        try:
            val = float(v)
            if not 0.0 <= val <= 1.0:
                raise ValueError("weight must be in [0,1]")
            out[SignalKind(k)] = val
        except ValueError as e:
            raise SystemExit(f"bad --weight {p!r}: {e}")
    return out


def run(case_path, kg_path, weights=None):
    kg = KnowledgeGraph.load(kg_path)
    case_id, _items, signals, custody = load_case(case_path)
    return assess(case_id, signals, kg, weights, custody)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="dragnet",
                                description="Evidence-to-actor attribution with ACH")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="assess one case file")
    a.add_argument("case")
    a.add_argument("--kg", default=str(DEFAULT_KG))
    a.add_argument("--weight", action="append", help="override a kind weight, e.g. imphash=0.2")
    a.add_argument("--format", choices=["md", "json"], default="md")
    a.add_argument("-o", "--out")
    d = sub.add_parser("demo", help="run all bundled synthetic scenarios")
    d.add_argument("--kg", default=str(DEFAULT_KG))
    args = p.parse_args(argv)

    if args.cmd == "assess":
        res = run(args.case, args.kg, parse_weights(args.weight))
        text = to_json(res) if args.format == "json" else to_markdown(res)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 0

    print(f"{'case':<30}{'leading':<14}{'confidence':<14}flags")
    for case in sorted(CASES.glob("*.json")):
        res = run(case, args.kg)
        print(f"{res.case_id:<30}{res.leading or '-':<14}{res.confidence.value:<14}"
              f"{len(res.false_flag_indicators)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
