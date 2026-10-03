"""DRAGNET command-line interface."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
from pathlib import Path

from . import __version__
from .ach import assess
from .graph import KnowledgeGraph
from .ingest import IngestError, load_case
from .models import Assessment, SignalKind
from .paths import FIXTURES, data_dir, download_hint
from .report import to_dict, to_json, to_markdown

DEFAULT_KG = FIXTURES / "campaigns.json"
CASES = FIXTURES / "cases"
REAL_CASES = FIXTURES / "real_cases"


class CliError(Exception):
    """A user-facing error: printed as one line, exit status 2."""


def parse_weights(pairs: list[str] | None) -> dict[SignalKind, float]:
    """Parse ``kind=weight`` overrides (weights in [0, 1])."""
    out = {}
    for p in pairs or []:
        k, _, v = p.partition("=")
        try:
            val = float(v)
            if not 0.0 <= val <= 1.0:
                raise ValueError("weight must be in [0,1]")
            out[SignalKind(k)] = val
        except ValueError as e:
            raise CliError(f"bad --weight {p!r}: {e}") from e
    return out


def _need(path: str | Path, what: str) -> Path:
    p = Path(path)
    if not p.is_file():
        raise CliError(f"{what} not found: {p}")
    return p


def run(case_path: str | Path, kg_path: str | Path,
        weights: dict[SignalKind, float] | None = None) -> Assessment:
    """Assess one case file against a knowledge-graph file."""
    kg = KnowledgeGraph.load(_need(kg_path, "knowledge graph (--kg)"))
    case_id, _items, signals, custody = load_case(_need(case_path, "case file"))
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
        raise CliError(f"{path} not found - {download_hint()}")
    attack = load_attack(path)
    misp = load_threat_actors(d / "misp-threat-actor.json") if (d / "misp-threat-actor.json").exists() else None
    mp = load_malpedia_families(d / "misp-malpedia.json") if (d / "misp-malpedia.json").exists() else None
    return attack, misp, mp, build_from_attack


def main(argv: list[str] | None = None) -> int:
    """Entry point of the ``dragnet`` command; returns the process exit status."""
    try:
        return _main(argv)
    except CliError as e:
        print(f"dragnet: error: {e}", file=sys.stderr)
        return 2
    except IngestError as e:
        print(f"dragnet: invalid case: {e}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"dragnet: invalid JSON: {e}", file=sys.stderr)
        return 2
    except ImportError as e:
        print(f"dragnet: missing optional dependency ({e.name or e}); install the extra, e.g. "
              'pip install "dragnet-attribution[api,sign]" (or pip install -e ".[api,sign]" in a checkout)',
              file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    fmt = argparse.ArgumentDefaultsHelpFormatter
    p = argparse.ArgumentParser(prog="dragnet", formatter_class=fmt,
                                description="Evidence-to-actor attribution with ACH")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, text: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=text, description=text, formatter_class=fmt)

    a = add("assess", "assess one case file")
    a.add_argument("case", help="case JSON ({case_id, evidence: [...]})")
    a.add_argument("--kg", default=str(DEFAULT_KG), help="knowledge-graph JSON (see build-kg)")
    a.add_argument("--weight", action="append", help="override a kind weight, e.g. imphash=0.2")
    a.add_argument("--format", choices=["md", "json", "stix"], default="md", help="report format")
    a.add_argument("--sign-key", help="Ed25519 private key PEM: sign the report body and custody chain "
                   "(writes the JSON report; not with --format stix)")
    a.add_argument("-o", "--out", help="write the report here instead of stdout")

    k = add("keygen", "create an Ed25519 key pair for signed custody")
    k.add_argument("prefix", help="writes <prefix>.key (mode 0600) and <prefix>.pub; keep keys outside the repo")
    k.add_argument("--force", action="store_true", help="overwrite existing key files")

    v = add("verify", "verify the custody chain (and signature) of a JSON report")
    v.add_argument("report", help="JSON report from assess --format json")
    v.add_argument("--pub", help="expected signer public key PEM (needed to prove who signed)")
    v.add_argument("--allow-unpinned", action="store_true",
                   help="accept a valid signature by the key embedded in the report (integrity only)")

    im = add("import", "build a case file from REVENANT / VITRINE JSON exports")
    im.add_argument("case_id", help="id of the new case")
    im.add_argument("--revenant", action="append", default=[], help="REVENANT export JSON")
    im.add_argument("--vitrine", action="append", default=[], help="VITRINE triage JSON")
    im.add_argument("-o", "--out", help="write the case here instead of stdout")

    d = add("demo", "run all bundled synthetic scenarios")
    d.add_argument("--kg", default=str(DEFAULT_KG), help="knowledge-graph JSON")

    b = add("build-kg", "build a knowledge graph from downloaded ATT&CK/MISP data")
    b.add_argument("--attack-version", default="19.2", help="ATT&CK Enterprise release")
    b.add_argument("--with-campaigns", action="store_true", help="also add ATT&CK campaigns")
    b.add_argument("--data", help="dataset dir (default $DRAGNET_DATA)")
    b.add_argument("-o", "--out", help="output JSON (default <data>/kg-attack-<ver>.json)")

    c = add("case-study", "run curated real cases (needs downloaded data)")
    c.add_argument("name", nargs="?", help="case id, e.g. olympic_destroyer_2018 (default: all)")
    c.add_argument("--mode", choices=["time-of-incident", "retrospective"], default="time-of-incident",
                   help="time-of-incident hides software first documented by the incident itself")
    c.add_argument("--attack-version", default="19.2", help="ATT&CK Enterprise release")
    c.add_argument("--data", help="dataset dir (default $DRAGNET_DATA)")
    c.add_argument("--format", choices=["md", "json", "summary"], default="summary", help="output format")

    x = add("export-cypher", "export a knowledge graph as a Neo4j Cypher script")
    x.add_argument("--kg", default=str(DEFAULT_KG), help="knowledge-graph JSON")
    x.add_argument("--case", help="also export this case and its observed signals")
    x.add_argument("-o", "--out", help="write the script here instead of stdout")

    s = add("serve", "run the optional FastAPI server (needs the [api] extra)")
    s.add_argument("--kg", default=str(DEFAULT_KG), help="knowledge-graph JSON")
    s.add_argument("--host", default="127.0.0.1", help="bind address (keep it on loopback)")
    s.add_argument("--port", type=int, default=8000, help="TCP port")
    s.add_argument("--allowed-host", action="append",
                   help="extra Host header value to accept (default: loopback names only)")
    return p


def _main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.cmd == "assess":
        if args.sign_key and args.format == "stix":
            raise CliError("--sign-key signs the JSON report only; use --format json (STIX bundles are not signed)")
        key = _need(args.sign_key, "signing key").read_bytes() if args.sign_key else None
        res = run(args.case, args.kg, parse_weights(args.weight))
        if args.format == "stix":
            from .stix import to_stix_json
            _emit(to_stix_json(res) + "\n", args.out)
        elif args.format == "json" or key is not None:      # signing implies the JSON report
            d = to_dict(res)
            if key is not None:
                from .custody import sign_entries
                d["custody_signature"] = sign_entries(res.custody, key, report=d)
            _emit(json.dumps(d, indent=2) + "\n", args.out)
        else:
            _emit(to_markdown(res), args.out)
        return 0

    if args.cmd == "keygen":
        from .custody import generate_keypair
        kp, pp = Path(args.prefix + ".key"), Path(args.prefix + ".pub")
        if not args.force and (kp.exists() or pp.exists()):
            raise CliError(f"{kp} or {pp} already exists (use --force to overwrite)")
        priv, pub = generate_keypair()
        if args.force:
            kp.unlink(missing_ok=True)
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(priv)
        pp.write_bytes(pub)
        print(f"wrote {kp} (private, unencrypted - keep it out of version control) and {pp}")
        return 0

    if args.cmd == "verify":
        from .custody import CustodyLog, verify_signed
        d = json.loads(_need(args.report, "report").read_text(encoding="utf-8"))
        entries = d.get("custody", [])
        if "custody_signature" in d:
            pub = _need(args.pub, "public key").read_bytes() if args.pub else None
            sig = d["custody_signature"]
            ok = verify_signed(entries, sig, pub, report=d)
            legacy = sig.get("version", 1) < 2
            what = ("chain + Ed25519 signature" if legacy else "report body + chain + Ed25519 signature") \
                + (" (pinned key)" if pub else " (embedded key)")
            if ok and legacy:
                print(f"LEGACY: {what} valid, but this v1 signature covers only the custody chain - the "
                      "verdict, scores and weights are NOT protected; re-sign the report to get a v2 signature")
                return 3
            if ok and pub is None:
                raw = bytes.fromhex(d["custody_signature"]["public_key"])
                print(f"signer key fingerprint (sha256): {hashlib.sha256(raw).hexdigest()[:16]}")
                if not args.allow_unpinned:
                    print(f"UNPINNED: {what} valid, but the signer is not verified - pass --pub "
                          "(or --allow-unpinned to accept integrity only)")
                    return 3
        else:
            log = CustodyLog()
            log.entries = entries
            ok, what = log.verify(), "hash chain (unsigned)"
        print(f"{'OK' if ok else 'FAILED'}: {what}, {len(entries)} entries")
        return 0 if ok else 1

    if args.cmd == "import":
        from .adapters import build_case_doc
        rev = [json.loads(_need(x, "REVENANT export").read_text(encoding="utf-8")) for x in args.revenant]
        vit = [json.loads(_need(x, "VITRINE export").read_text(encoding="utf-8")) for x in args.vitrine]
        if not rev and not vit:
            raise CliError("give at least one --revenant or --vitrine export")
        _emit(json.dumps(build_case_doc(args.case_id, rev, vit), indent=2) + "\n", args.out)
        return 0

    if args.cmd == "demo":
        cases = sorted(CASES.glob("*.json"))
        if not cases:
            raise CliError(f"no demo cases found in {CASES}")
        print(f"{'case':<30}{'leading':<14}{'confidence':<14}flags")
        for case in cases:
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
                raise CliError(f"unknown case {args.name!r}")
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
        kg = KnowledgeGraph.load(_need(args.kg, "knowledge graph (--kg)"))
        res = sigs = None
        if args.case:
            case_id, _i, sigs, custody = load_case(_need(args.case, "case file"))
            res = assess(case_id, sigs, kg, custody=custody)
        _emit(to_cypher(kg, res, sigs), args.out)
        return 0

    if args.cmd == "serve":  # pragma: no cover - network server
        import uvicorn

        from .api import DEFAULT_HOSTS, create_app
        try:
            loopback = ipaddress.ip_address(args.host).is_loopback
        except ValueError:
            loopback = args.host == "localhost"
        if not loopback:
            print(f"WARNING: binding to {args.host}; the API has no authentication - expose it only "
                  "on a trusted network and pass --allowed-host for the name clients use", file=sys.stderr)
        hosts = [*DEFAULT_HOSTS, *(args.allowed_host or [])]
        uvicorn.run(create_app(_need(args.kg, "knowledge graph (--kg)"), hosts), host=args.host, port=args.port)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
