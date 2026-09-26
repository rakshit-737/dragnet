"""DRAGNET command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ach import assess
from .graph import KnowledgeGraph
from .ingest import load_case
from .models import SignalKind
from .paths import FIXTURES, data_dir
from .report import to_json, to_markdown

DEFAULT_KG = FIXTURES / "campaigns.json"
CASES = FIXTURES / "cases"
REAL_CASES = FIXTURES / "real_cases"


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


def _emit(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.write(text)


def _load_real(args):
    from .kg_build import build_from_attack
    from .sources.attack import load_attack
    from .sources.misp import load_malpedia_families, load_threat_actors
    d = Path(args.data) if getattr(args, "data", None) else data_dir()
    path = d / f"enterprise-attack-{args.attack_version}.json"
    if not path.exists():
        raise SystemExit(f"{path} not found - run: python scripts/download_data.py")
    attack = load_attack(path)
    misp = load_threat_actors(d / "misp-threat-actor.json") if (d / "misp-threat-actor.json").exists() else None
    mp = load_malpedia_families(d / "misp-malpedia.json") if (d / "misp-malpedia.json").exists() else None
    return attack, misp, mp, build_from_attack


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="dragnet",
                                description="Evidence-to-actor attribution with ACH")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("assess", help="assess one case file")
    a.add_argument("case")
    a.add_argument("--kg", default=str(DEFAULT_KG), help="knowledge-graph JSON (see build-kg)")
    a.add_argument("--weight", action="append", help="override a kind weight, e.g. imphash=0.2")
    a.add_argument("--format", choices=["md", "json"], default="md")
    a.add_argument("-o", "--out")

    d = sub.add_parser("demo", help="run all bundled synthetic scenarios")
    d.add_argument("--kg", default=str(DEFAULT_KG))

    b = sub.add_parser("build-kg", help="build a knowledge graph from downloaded ATT&CK/MISP data")
    b.add_argument("--attack-version", default="19.2")
    b.add_argument("--with-campaigns", action="store_true", help="also add ATT&CK campaigns")
    b.add_argument("--data", help="dataset dir (default $DRAGNET_DATA)")
    b.add_argument("-o", "--out", help="output JSON (default <data>/kg-attack-<ver>.json)")

    c = sub.add_parser("case-study", help="run curated real cases (needs downloaded data)")
    c.add_argument("name", nargs="?", help="case id, e.g. olympic_destroyer_2018 (default: all)")
    c.add_argument("--mode", choices=["time-of-incident", "retrospective"], default="time-of-incident")
    c.add_argument("--attack-version", default="19.2")
    c.add_argument("--data")
    c.add_argument("--format", choices=["md", "json", "summary"], default="summary")

    x = sub.add_parser("export-cypher", help="export a knowledge graph as a Neo4j Cypher script")
    x.add_argument("--kg", default=str(DEFAULT_KG))
    x.add_argument("--case", help="also export this case and its observed signals")
    x.add_argument("-o", "--out")

    s = sub.add_parser("serve", help="run the optional FastAPI server")
    s.add_argument("--kg", default=str(DEFAULT_KG))
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)

    args = p.parse_args(argv)

    if args.cmd == "assess":
        res = run(args.case, args.kg, parse_weights(args.weight))
        _emit(to_json(res) if args.format == "json" else to_markdown(res), args.out)
        return 0

    if args.cmd == "demo":
        print(f"{'case':<30}{'leading':<14}{'confidence':<14}flags")
        for case in sorted(CASES.glob("*.json")):
            res = run(case, args.kg)
            print(f"{res.case_id:<30}{res.leading or '-':<14}{res.confidence.value:<14}"
                  f"{len(res.false_flag_indicators)}")
        return 0

    if args.cmd == "build-kg":
        attack, misp, mp, build = _load_real(args)
        kg = build(attack, misp=misp, malpedia=mp, include_campaigns=args.with_campaigns)
        out = Path(args.out) if args.out else (Path(args.data) if args.data else data_dir()) / \
            f"kg-attack-{attack.version}.json"
        kg.save(out)
        print(f"wrote {out}: {len(kg.actors)} actors, {len(kg.campaigns)} campaign nodes, "
              f"{len(kg.index)} signal keys")
        return 0

    if args.cmd == "case-study":
        from .cases import addition_campaigns, load_real_cases
        attack, misp, mp, build = _load_real(args)
        cases = load_real_cases(REAL_CASES, attack)
        if args.name:
            cases = [k for k in cases if k.case_id == args.name]
            if not cases:
                raise SystemExit(f"unknown case {args.name!r}")
        names = {g.attack_id: g.name for g in attack.groups.values()}
        for case in cases:
            hide = set(case.novel_software) if args.mode == "time-of-incident" else set()
            base = build(attack, misp=misp, malpedia=mp, exclude_software=hide)
            kg = KnowledgeGraph(list(base.campaigns.values()) + addition_campaigns(case, attack),
                                base.actor_meta, base.meta)
            res = assess(case.case_id, case.signals, kg)
            if args.format == "md":
                _emit(to_markdown(res) + "\n", None)
            elif args.format == "json":
                _emit(to_json(res) + "\n", None)
            else:
                truth = ", ".join(names.get(g, g) for g in case.ground_truth) or "(none)"
                print(f"{case.case_id:<28} verdict={res.leading or '-':<16} "
                      f"{res.confidence.value:<13} flags={len(res.false_flag_indicators)}  truth={truth}")
        return 0

    if args.cmd == "export-cypher":
        from .neo4j_export import to_cypher
        kg = KnowledgeGraph.load(args.kg)
        res = sigs = None
        if args.case:
            case_id, _i, sigs, custody = load_case(args.case)
            res = assess(case_id, sigs, kg, custody=custody)
        _emit(to_cypher(kg, res, sigs), args.out)
        return 0

    if args.cmd == "serve":  # pragma: no cover - network server
        import uvicorn

        from .api import create_app
        uvicorn.run(create_app(args.kg), host=args.host, port=args.port)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
