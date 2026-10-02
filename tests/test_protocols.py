"""Leave-report-out protocol, per-report cases and the statistics helpers."""
import json

import pytest

from dragnet import bench
from dragnet import protocols as P
from dragnet.graph import KnowledgeGraph
from dragnet.models import Campaign, Signal, SignalKind
from dragnet.sources.attack import load_attack


def _ref(name):
    return {"source_name": name, "description": name}


def _bundle():
    tech = [{"type": "attack-pattern", "id": f"attack-pattern--{i}", "name": f"T{i}",
             "external_references": [{"source_name": "mitre-attack", "external_id": f"T10{i:02d}"}]} for i in range(6)]
    grp = {"type": "intrusion-set", "id": "intrusion-set--g", "name": "Grp", "aliases": ["Grp"],
           "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}]}
    camp = {"type": "campaign", "id": "campaign--c", "name": "Op", "first_seen": "2020-01-01T00:00:00Z",
            "external_references": [{"source_name": "mitre-attack", "external_id": "C0001"}, _ref("Vendor Op March 2020")]}

    def rel(i, src, dst, refs, rt="uses"):
        return {"type": "relationship", "id": f"relationship--{i}", "relationship_type": rt,
                "source_ref": src, "target_ref": dst, "external_references": [_ref(r) for r in refs]}
    rels = [rel(0, "intrusion-set--g", "attack-pattern--0", ["Vendor Op March 2020"]),            # only campaign report
            rel(1, "intrusion-set--g", "attack-pattern--1", ["Vendor Op March 2020", "Other 2018"]),
            rel(2, "intrusion-set--g", "attack-pattern--2", []),                                  # uncited
            rel(3, "intrusion-set--g", "attack-pattern--3", ["Other 2018"]),
            rel(4, "intrusion-set--g", "attack-pattern--4", ["Other 2018"]),
            rel(5, "campaign--c", "attack-pattern--0", ["Vendor Op March 2020"]),
            rel(6, "campaign--c", "intrusion-set--g", ["Vendor Op March 2020"], "attributed-to")]
    return {"type": "bundle", "objects": [{"type": "x-mitre-collection", "id": "x", "x_mitre_version": "1",
                                          "modified": "2026"}, *tech, grp, camp, *rels]}


@pytest.fixture
def attack(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps(_bundle()))
    return load_attack(p)


def test_drop_cited_removes_only_report_only_edges(attack):
    refs = P.campaign_refs(attack, "campaign--c")
    assert refs == {"Vendor Op March 2020"}
    a2 = P.drop_cited(attack, refs)
    assert attack.techniques_of("intrusion-set--g") == {"T1000", "T1001", "T1002", "T1003", "T1004"}
    assert a2.techniques_of("intrusion-set--g") == {"T1001", "T1002", "T1003", "T1004"}
    assert a2.techniques_of("campaign--c") == {"T1000"}          # campaign edges untouched


def test_report_cases_and_years(attack):
    cases = P.report_cases(attack, min_ttps=2)
    by = {c.meta["report"]: c for c in cases}
    assert set(by) == {"Other 2018", "Vendor Op March 2020"}
    assert {s.value for s in by["Other 2018"].signals} == {"T1001", "T1003", "T1004"}
    assert by["Other 2018"].truth == {"Grp"} and by["Other 2018"].meta["year"] == 2018
    assert P.ref_year("FireEye APT28 October 2014") == 2014 and P.ref_year("no year") is None


def test_clopper_pearson_known_values():
    lo, hi = P.clopper_pearson(0, 25)
    assert lo == 0 and abs(hi - 0.1372) < 1e-3
    lo, hi = P.clopper_pearson(25, 25)
    assert hi == 1 and abs(lo - 0.8628) < 1e-3


def test_sign_flip_exact_and_holm():
    r = P.sign_flip_test([1, 1, 1, 1] + [0] * 20)
    assert r["n_discordant"] == 4 and r["p_one_sided"] == pytest.approx(1 / 16)
    adj = P.holm({"a": 0.01, "b": 0.04, "c": 0.5})
    assert adj == {"a": 0.03, "b": 0.08, "c": 0.5}


def test_isotonic_is_monotone():
    iso = P.Isotonic().fit([0.1, 0.2, 0.3, 0.4, 0.5], [0, 1, 0, 1, 1])
    ys = [iso(x) for x in (0.05, 0.15, 0.25, 0.35, 0.45, 0.9)]
    assert ys == sorted(ys) and ys[-1] == 1.0


def test_risk_coverage_ties_in_expectation():
    rc = P.risk_coverage([(1.0, 1), (1.0, 0), (0.5, 1), (0.1, 0)])
    assert rc["risk_at"]["0.2"] == pytest.approx(0.5)      # first case drawn from a 50/50 tie
    assert rc["risk_at"]["1.0"] == pytest.approx(0.5)


def test_baseline_abstains_on_ties():
    kg = KnowledgeGraph([Campaign("c1", "c", "aaa", [Signal(SignalKind.FAMILY, "x")]),
                         Campaign("c2", "c", "menuPass", [Signal(SignalKind.FAMILY, "x")])])
    p = bench.METHODS["ioc-correlation"]([Signal(SignalKind.FAMILY, "x")], kg)
    assert p.named is None and set(p.scores) == {"aaa", "menuPass"}
    s = bench.evaluate("ioc-correlation", [bench.Case("k", "k", [Signal(SignalKind.FAMILY, "x")], {"aaa"})], kg)
    assert s["confident_error_rate"] == 0 and s["confident_error_expect"] == pytest.approx(0.5)
