import json
from pathlib import Path

import pytest

from dragnet.ach import FALSE_FLAG, UNKNOWN, assess, noisy_or
from dragnet.cli import main, parse_weights, run
from dragnet.custody import CustodyLog, canonical_hash
from dragnet.graph import KnowledgeGraph
from dragnet.ingest import IngestError, build_case, extract_signals
from dragnet.models import Confidence, EvidenceItem, Signal, SignalKind
from dragnet.report import to_json, to_markdown

ROOT = Path(__file__).resolve().parent.parent
KG = ROOT / "fixtures" / "campaigns.json"
CASES = ROOT / "fixtures" / "cases"


@pytest.fixture
def kg():
    return KnowledgeGraph.load(KG)


def case(name, **kw):
    return run(CASES / f"{name}.json", KG, kw.get("weights"))


# --- scenarios from the spec ---------------------------------------------

def test_scenario1_correct_attribution():
    a = case("wannacry_like")
    assert a.leading == "LAZARUS_SIM"
    assert a.confidence in (Confidence.HIGH, Confidence.MEDIUM)
    assert not a.false_flag_indicators


def test_scenario2_false_flag_withheld():
    a = case("olympic_destroyer_like")
    assert a.confidence not in (Confidence.HIGH, Confidence.MEDIUM)
    assert a.false_flag_indicators
    assert any("forgeable" in f for f in a.false_flag_indicators)


def test_scenario3_multi_signal_boost(kg):
    a = case("multi_signal_boost")
    top = next(h for h in a.hypotheses if h.hypothesis == "SANDWORM_SIM")
    for sig in top.matched:
        single = assess("x", [sig], kg)
        s1 = next(h for h in single.hypotheses if h.hypothesis == "SANDWORM_SIM")
        assert top.score > s1.score
    assert a.confidence == Confidence.HIGH


def test_scenario4_weight_flip_is_transparent():
    base = case("multi_signal_boost")
    flipped = case("multi_signal_boost",
                   weights={SignalKind.IMPHASH: 0.0, SignalKind.IP: 0.0})
    b = next(h for h in base.hypotheses if h.hypothesis == "SANDWORM_SIM").score
    f = next(h for h in flipped.hypotheses if h.hypothesis == "SANDWORM_SIM").score
    assert f < b
    assert flipped.weights["imphash"] == 0.0
    assert flipped.confidence == Confidence.INSUFFICIENT


def test_scenario5_thin_evidence_insufficient():
    a = case("thin_evidence")
    assert a.leading is None and a.confidence == Confidence.INSUFFICIENT


# --- engine properties -----------------------------------------------------

def test_mandatory_meta_hypotheses_always_present(kg):
    a = assess("empty", [], kg)
    names = {h.hypothesis for h in a.hypotheses}
    assert {FALSE_FLAG, UNKNOWN} <= names
    assert a.confidence == Confidence.INSUFFICIENT


def test_noisy_or_bounds():
    assert noisy_or([]) == 0.0
    assert noisy_or([1.0]) == 1.0
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert noisy_or([2.0, -1.0]) == 1.0


def test_matrix_marks_inconsistent(kg):
    a = case("olympic_destroyer_like")
    row = a.matrix["ip:198.51.100.23"]
    assert row["SANDWORM_SIM"] == "C" and row["LAZARUS_SIM"] == "I"
    assert a.matrix["rich_header:rh:9f8e7d6c"][FALSE_FLAG] == "C"


def test_forgeable_only_never_attributes(kg):
    a = assess("rh", [Signal(SignalKind.RICH_HEADER, "rh:9f8e7d6c"),
                      Signal(SignalKind.LANGUAGE, "locale:ru-RU")], kg)
    assert a.leading is None


def test_graph_links_and_edges(kg):
    s = Signal(SignalKind.CODE_REUSE, "FN:RC4_VARIANT_0x3F", "EV1")  # case-insensitive
    assert kg.actors_for(s) == {"LAZARUS_SIM"}
    edges = kg.edges([s])
    assert {e[2] for e in edges} == {"C-LZ-2017-RANSOM", "C-LZ-2016-BANK"}


# --- ingestion + custody --------------------------------------------------

def test_extract_signals_and_dedupe():
    item = EvidenceItem("E", "malware", {"imphash": "AB", "ttps": ["T1", "T1"], "family": None})
    sigs = extract_signals(item)
    assert [s.label for s in sigs] == ["imphash:AB", "ttp:T1"]
    assert all(s.source == "E" for s in sigs)


@pytest.mark.parametrize("bad", [
    {"evidence": []},
    {"case_id": "x", "evidence": [{"id": "a", "kind": "pcap"}]},
    {"case_id": "x", "evidence": [{"kind": "forensic"}]},
    {"case_id": "x", "evidence": [{"id": "a", "kind": "forensic", "content": {"ttps": {"a": 1}}}]},
])
def test_ingest_rejects_malformed(bad):
    with pytest.raises(IngestError):
        build_case(bad)


def test_custody_chain_verifies_and_detects_tamper():
    _, items, _, log = build_case(json.loads((CASES / "wannacry_like.json").read_text()))
    assert items[0].sha256 == canonical_hash(items[0].content)
    assert log.verify()
    log.entries[0]["item_hash"] = "f" * 64
    assert not log.verify()


def test_custody_detects_reorder():
    log = CustodyLog()
    log.record("a", "1", "h1", ts="t")
    log.record("b", "2", "h2", ts="t")
    log.entries.reverse()
    assert not log.verify()


def test_assessment_records_custody_entry():
    a = case("wannacry_like")
    assert a.custody[-1]["action"] == "assess"


# --- reporting + CLI ------------------------------------------------------

def test_reports_render():
    a = case("olympic_destroyer_like")
    md = to_markdown(a)
    assert "ACH matrix" in md and "Insufficient for attribution" in md
    d = json.loads(to_json(a))
    assert d["confidence"] == "INSUFFICIENT" and d["ach_matrix"]


def test_cli_assess_json(tmp_path, capsys):
    out = tmp_path / "r.json"
    assert main(["assess", str(CASES / "wannacry_like.json"), "--format", "json",
                 "-o", str(out), "--weight", "ttp=0.1"]) == 0
    assert json.loads(out.read_text())["leading"] == "LAZARUS_SIM"


def test_cli_demo(capsys):
    assert main(["demo"]) == 0
    assert "olympic_destroyer_like" in capsys.readouterr().out


def test_parse_weights_rejects_bad():
    with pytest.raises(SystemExit):
        parse_weights(["imphash=2"])
    with pytest.raises(SystemExit):
        parse_weights(["nope=0.1"])
