"""STIX export, signed custody, REVENANT/VITRINE adapters, bootstrap CIs."""
import json
from pathlib import Path

import pytest

from dragnet import bench
from dragnet.adapters import build_case_doc, from_revenant, from_vitrine
from dragnet.cli import main, run
from dragnet.report import to_dict
from dragnet.stix import GRADE_TO_STIX, to_stix

ROOT = Path(__file__).resolve().parent.parent
KG = ROOT / "dragnet" / "data" / "campaigns.json"
CASES = ROOT / "dragnet" / "data" / "cases"
ADAPT = ROOT / "fixtures" / "adapters"


# ------------------------------------------------------------------ STIX
def test_stix_bundle_structure():
    a = run(CASES / "wannacry_like.json", KG)
    b = to_stix(a, created="2026-01-01T00:00:00.000Z")
    assert b["type"] == "bundle"
    types = [o["type"] for o in b["objects"]]
    assert types.count("report") == 1 and "campaign" in types and "note" in types
    ids = {o["id"] for o in b["objects"]}
    for o in b["objects"]:
        for ref in o.get("object_refs", []):
            assert ref in ids
        if o["type"] != "bundle":
            assert o["spec_version"] == "2.1"
    rel = next(o for o in b["objects"] if o["type"] == "relationship")
    assert rel["relationship_type"] == "attributed-to"
    assert rel["confidence"] == GRADE_TO_STIX[a.confidence.value]
    assert any(o["type"] == "attack-pattern" for o in b["objects"])


def test_stix_deterministic_and_no_actor_when_withheld():
    a = run(CASES / "thin_evidence.json", KG)
    b1 = to_stix(a, created="2026-01-01T00:00:00.000Z")
    b2 = to_stix(a, created="2026-01-01T00:00:00.000Z")
    assert b1 == b2
    assert a.leading is None
    assert not any(o["type"] in ("intrusion-set", "relationship") for o in b1["objects"])


def test_cli_stix(tmp_path):
    out = tmp_path / "r.json"
    assert main(["assess", str(CASES / "wannacry_like.json"), "--kg", str(KG), "--format", "stix",
                 "-o", str(out)]) == 0
    assert json.loads(out.read_text())["type"] == "bundle"


# ------------------------------------------------------------------ signed custody
def test_signed_custody_roundtrip(tmp_path):
    pytest.importorskip("cryptography")
    from dragnet.custody import generate_keypair, sign_entries, verify_signed
    priv, pub = generate_keypair()
    a = run(CASES / "wannacry_like.json", KG)
    sig = sign_entries(a.custody, priv)
    assert verify_signed(a.custody, sig, pub)
    assert verify_signed(a.custody, sig)                    # embedded key
    tampered = [dict(e) for e in a.custody]
    tampered[0]["item_hash"] = "0" * 64
    assert not verify_signed(tampered, sig, pub)
    _, other = generate_keypair()
    assert not verify_signed(a.custody, sig, other)         # wrong signer
    assert not verify_signed(a.custody[:-1], sig, pub)      # truncated


def test_cli_keygen_sign_verify(tmp_path, capsys):
    pytest.importorskip("cryptography")
    pre = str(tmp_path / "k")
    assert main(["keygen", pre]) == 0
    rep = tmp_path / "r.json"
    assert main(["assess", str(CASES / "wannacry_like.json"), "--kg", str(KG), "--sign-key", pre + ".key",
                 "-o", str(rep)]) == 0
    assert "custody_signature" in json.loads(rep.read_text())
    assert main(["verify", str(rep), "--pub", pre + ".pub"]) == 0
    assert main(["verify", str(rep)]) == 3                     # valid but signer not pinned
    assert main(["verify", str(rep), "--allow-unpinned"]) == 0
    assert main(["keygen", pre]) == 2                          # refuses to overwrite
    d = json.loads(rep.read_text())
    d["custody"][0]["action"] = "forged"
    rep.write_text(json.dumps(d))
    assert main(["verify", str(rep), "--pub", pre + ".pub"]) == 1


def test_signature_covers_the_verdict(tmp_path):
    """Editing the verdict, confidence, flags, scores or weights of a signed report must fail
    verification, not only edits to the custody entries."""
    pytest.importorskip("cryptography")
    pre = str(tmp_path / "k")
    assert main(["keygen", pre]) == 0
    rep = tmp_path / "r.json"
    assert main(["assess", str(CASES / "olympic_destroyer_like.json"), "--kg", str(KG), "--sign-key", pre + ".key",
                 "-o", str(rep)]) == 0
    orig = json.loads(rep.read_text())
    assert orig["custody_signature"]["version"] == 2
    edits = [lambda d: d.__setitem__("leading", "SANDWORM_SIM"),
             lambda d: d.__setitem__("confidence", "HIGH"),
             lambda d: d.__setitem__("false_flag_indicators", []),
             lambda d: d["hypotheses"][0].__setitem__("score", 0.99),
             lambda d: d["weights"].__setitem__("imphash", 0.99)]
    for edit in edits:
        d = json.loads(json.dumps(orig))
        edit(d)
        rep.write_text(json.dumps(d))
        assert main(["verify", str(rep), "--pub", pre + ".pub"]) == 1
    rep.write_text(json.dumps(orig, indent=4))                 # re-serialising is not tampering
    assert main(["verify", str(rep), "--pub", pre + ".pub"]) == 0


def test_legacy_chain_only_signature_is_flagged(tmp_path):
    pytest.importorskip("cryptography")
    from dragnet.custody import generate_keypair, sign_entries
    priv, pub = generate_keypair()
    a = run(CASES / "wannacry_like.json", KG)
    d = to_dict(a)
    d["custody_signature"] = sign_entries(a.custody, priv)          # v1: chain head only
    rep, pk = tmp_path / "r.json", tmp_path / "k.pub"
    rep.write_text(json.dumps(d))
    pk.write_bytes(pub)
    assert main(["verify", str(rep), "--pub", str(pk)]) == 3


def test_cli_stix_refuses_sign_key(tmp_path, capsys):
    assert main(["assess", str(CASES / "wannacry_like.json"), "--kg", str(KG), "--format", "stix",
                 "--sign-key", str(tmp_path / "missing.key"), "-o", str(tmp_path / "s.json")]) == 2
    assert "--sign-key" in capsys.readouterr().err
    assert not (tmp_path / "s.json").exists()


def test_cli_missing_sign_key_is_an_error(tmp_path):
    assert main(["assess", str(CASES / "wannacry_like.json"), "--kg", str(KG),
                 "--sign-key", str(tmp_path / "missing.key")]) == 2


def test_cli_verify_unsigned(tmp_path):
    rep = tmp_path / "r.json"
    assert main(["assess", str(CASES / "wannacry_like.json"), "--kg", str(KG), "--format", "json",
                 "-o", str(rep)]) == 0
    assert main(["verify", str(rep)]) == 0


# ------------------------------------------------------------------ adapters
def test_from_revenant():
    doc = json.loads((ADAPT / "revenant_export.json").read_text())
    item, notes = from_revenant(doc)
    c = item["content"]
    assert item["kind"] == "forensic"
    assert "T1486" in c["ttps"] and "T1210" in c["ttps"]
    assert "203.0.113.7" in c["network_connections"]
    assert "10.0.0.5" not in c["network_connections"]           # private address dropped
    assert "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" in c["dns_queries"]
    assert c.get("tools") == ["mssecsvc", "tasksche"]                       # stock binaries dropped
    assert notes and "timestomp" in notes[0]


def test_from_vitrine():
    doc = json.loads((ADAPT / "vitrine_triage.json").read_text())
    item = from_vitrine(doc)
    assert item["kind"] == "malware"
    assert item["content"]["family"] == "WannaCry"
    assert item["content"]["ttps"] == ["T1486", "T1490"]
    assert item["content"]["imphash"]


def test_cli_import_then_assess(tmp_path):
    out = tmp_path / "case.json"
    assert main(["import", "incident-1", "--revenant", str(ADAPT / "revenant_export.json"),
                 "--vitrine", str(ADAPT / "vitrine_triage.json"), "-o", str(out)]) == 0
    case = json.loads(out.read_text())
    assert [e["kind"] for e in case["evidence"]] == ["forensic", "malware"]
    a = run(out, KG)
    assert a.case_id == "incident-1" and a.custody


def test_build_case_doc_empty():
    assert build_case_doc("x")["evidence"] == []


# ------------------------------------------------------------------ bootstrap
def _rows(vals):
    return [{"in_kg": True, "named": "A" if v else None, "grade": None, "named_ok": bool(v), "top1": float(v),
             "top3": float(v), "top5": float(v), "rr": float(v), "brier": 0.0, "p_leader": 0.5,
             "leader_ok": bool(v)} for v in vals]


def test_bootstrap_ci_brackets_mean():
    rows = _rows([1, 0, 1, 1, 0, 1, 0, 1, 1, 1])
    ci = bench.bootstrap_ci(rows, n_boot=500)
    lo, hi = ci["top1"]
    assert lo <= 0.7 <= hi and 0 <= lo < hi <= 1
    assert bench.bootstrap_ci(rows, n_boot=500) == ci     # seeded


def test_paired_bootstrap_diff():
    a, b = _rows([1] * 10), _rows([0] * 10)
    d = bench.paired_bootstrap_diff(a, b, n_boot=200)
    assert d["diff"] == 1.0 and d["ci"] == [1.0, 1.0] and d["p_le_0"] == 0


def test_markdown_report_escapes_hostile_strings():
    from dragnet.graph import KnowledgeGraph
    from dragnet.ingest import build_case
    from dragnet.report import to_markdown
    case = {"case_id": "demo<script>alert(1)</script>", "evidence": [
        {"id": "EV1<b>x</b>", "kind": "forensic",
         "content": {"mutexes": ["GlobalMtx` <img src=x onerror=alert(document.domain)> `"]}}]}
    cid, _i, sigs, custody = build_case(case)
    from dragnet.ach import assess
    md = to_markdown(assess(cid, sigs, KnowledgeGraph.load(KG), custody=custody))
    assert "<script>" not in md and "<img" not in md and "<b>x</b>" not in md
    assert "&lt;img" in md
