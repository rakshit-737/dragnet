"""Tests for the real-data pipeline, run on tiny committed fixtures (no downloads)."""
import io
import json
import zipfile
from pathlib import Path

import pytest

from dragnet import bench
from dragnet.ach import EngineConfig, assess
from dragnet.cases import addition_campaigns, load_real_cases
from dragnet.graph import KnowledgeGraph, ttp_expand
from dragnet.kg_build import (build_from_attack, enrich_bazaar, enrich_threatfox,
                              family_actor_map, imphash_family_index, software_aliases)
from dragnet.models import Campaign, Confidence, Signal, SignalKind
from dragnet.sources.abusech import BazaarSample, ThreatFoxIOC, iter_bazaar, iter_threatfox
from dragnet.sources.aptnotes import load_aptnotes, report_counts
from dragnet.sources.attack import load_attack
from dragnet.sources.misp import alias_index, load_malpedia_families, load_threat_actors, norm

ROOT = Path(__file__).resolve().parent.parent
MINI = ROOT / "fixtures" / "mini"


@pytest.fixture(scope="module")
def attack():
    return load_attack(MINI / "attack-mini.json")


@pytest.fixture(scope="module")
def misp():
    return load_threat_actors(MINI / "misp-threat-actor-mini.json")


@pytest.fixture(scope="module")
def malpedia():
    return load_malpedia_families(MINI / "misp-malpedia-mini.json")


@pytest.fixture(scope="module")
def kg(attack, misp, malpedia):
    return build_from_attack(attack, misp=misp, malpedia=malpedia)


# --- sources ------------------------------------------------------------------

def test_attack_loader_drops_revoked_and_links(attack):
    assert {g.name for g in attack.groups.values()} == {"Red Group", "Blue Group", "Green Group"}
    red = next(k for k, g in attack.groups.items() if g.name == "Red Group")
    assert attack.techniques_of(red) == {"T1001", "T1002", "T1003", "T1059.001"}
    assert len(attack.attributed) == 2 and attack.version == "0.1"
    sw_attr = attack.software_attribution()
    mimi = next(k for k, s in attack.software.items() if s.name == "Mimikatz")
    assert len(sw_attr[mimi]) == 3


def test_misp_country_and_aliases(misp):
    by = {a.name: a for a in misp}
    assert by["Red Group"].country == "RU"
    assert by["Blue Group"].country == "KP"   # via cfr-suspected-state-sponsor
    assert alias_index(misp)[norm("azure-bear")].name == "Blue Group"


def test_software_aliases_merge_malpedia(attack, malpedia):
    al = software_aliases(attack, malpedia)
    red = next(k for k, s in attack.software.items() if s.name == "RedRAT")
    assert "Rouge RAT" in al[red] and "CrimsonRAT-X" in al[red]


def test_aptnotes_counts(kg):
    reports = load_aptnotes(MINI / "APTnotes-mini.csv")
    c = report_counts(reports, kg.actor_meta)
    assert c["Blue Group"] == 2 and c["Red Group"] == 1 and c["Green Group"] == 0


def test_abusech_parsers(tmp_path):
    tf = {"1": [{"ioc_value": "198.51.100.7:443", "ioc_type": "ip:port", "malware": "win.redrat",
                 "malware_printable": "RedRAT", "first_seen_utc": "2023-01-01 00:00:00",
                 "confidence_level": 90}]}
    zp = tmp_path / "tf.json.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("full.json", json.dumps(tf))
    iocs = list(iter_threatfox(zp))
    assert iocs[0].malware_printable == "RedRAT" and iocs[0].confidence == 90
    csv_text = ('# header\n"2023-01-01 00:00:00", "AA", "m", "s", "r", "f", "exe", "mime", "RedRAT", '
                '"n/a", "n/a", "ABCDEF", "ss", "T1"\n')
    bp = tmp_path / "b.csv.zip"
    with zipfile.ZipFile(bp, "w") as z:
        z.writestr("full.csv", csv_text)
    s = list(iter_bazaar(bp))[0]
    assert s.sha256 == "aa" and s.imphash == "abcdef" and s.signature == "RedRAT"


# --- graph --------------------------------------------------------------------

def test_kg_build_layers(kg):
    assert set(kg.actors) == {"Red Group", "Blue Group", "Green Group"}
    assert kg.country("Red Group") == "RU"
    mimi = Signal(SignalKind.TOOL, "mimikatz")
    assert kg.specificity(mimi) == pytest.approx(1 / 3)
    assert kg.specificity(Signal(SignalKind.FAMILY, "rouge rat")) == 1.0   # malpedia synonym
    assert Signal(SignalKind.LANGUAGE, "lang:ru").key in kg.index


def test_ttp_expand_and_similarity(kg):
    assert ttp_expand(["t1059.001"]) == {"T1059.001", "T1059"}
    sim = kg.ttp_similarity(["T1001", "T1002"])
    assert max(sim, key=sim.get) == "Red Group"
    # sub-technique evidence matches parent in another profile
    assert "Green Group" in kg.ttp_similarity(["T1059.001"])


def test_kg_roundtrip(tmp_path, kg):
    p = tmp_path / "kg.json"
    kg.save(p)
    kg2 = KnowledgeGraph.load(p)
    assert kg2.actors == kg.actors and kg2.country("Red Group") == "RU"


def test_exclude_software_hides_family(attack, misp):
    kg = build_from_attack(attack, misp=misp, exclude_software={"S9001"})
    assert not kg.actors_for(Signal(SignalKind.FAMILY, "RedRAT"))


def test_include_campaigns(attack):
    kg = build_from_attack(attack, include_campaigns=True)
    assert "C9001" in kg.campaigns and kg.campaigns["C9001"].actor == "Red Group"


def test_enrichment(attack, kg):
    fam = family_actor_map(attack)
    assert fam[norm("RedRAT")] == {"Red Group"} and norm("Mimikatz") not in fam
    iocs = [ThreatFoxIOC("198.51.100.7:443", "ip:port", "win.redrat", "RedRAT", "2023", 90),
            ThreatFoxIOC("low.example", "domain", "win.redrat", "RedRAT", "2023", 10)]
    kg2, hits = enrich_threatfox(kg, attack, iocs)
    assert kg2.actors_for(Signal(SignalKind.IP, "198.51.100.7")) == {"Red Group"}
    assert not kg2.actors_for(Signal(SignalKind.DOMAIN, "low.example"))
    samples = [BazaarSample("2022", "a", "exe", "RedRAT", "aaaa", ""),
               BazaarSample("2022", "b", "exe", "BlueWiper", "shared", ""),
               BazaarSample("2022", "c", "exe", "Other1", "shared", ""),
               BazaarSample("2022", "d", "exe", "Other2", "shared", ""),
               BazaarSample("2025", "e", "exe", "RedRAT", "late", "")]
    gi = imphash_family_index(samples)
    kg3, hits = enrich_bazaar(kg, attack, samples, before="2024", global_index=gi)
    assert kg3.actors_for(Signal(SignalKind.IMPHASH, "aaaa")) == {"Red Group"}
    assert not kg3.actors_for(Signal(SignalKind.IMPHASH, "shared"))   # collision-filtered
    assert not kg3.actors_for(Signal(SignalKind.IMPHASH, "late"))     # temporal split


# --- engine on real-shaped graphs --------------------------------------------

def test_commodity_tool_alone_is_insufficient(kg):
    a = assess("x", [Signal(SignalKind.TOOL, "Mimikatz"), Signal(SignalKind.TTP, "T1003")], kg)
    assert a.leading is None and a.confidence == Confidence.INSUFFICIENT


def test_exclusive_family_plus_ttps_attributes(kg):
    sigs = [Signal(SignalKind.FAMILY, "RedRAT"), Signal(SignalKind.TTP, "T1001"),
            Signal(SignalKind.TTP, "T1002")]
    a = assess("x", sigs, kg)
    assert a.leading == "Red Group"
    assert a.posterior["Red Group"] == max(a.posterior.values())


def test_cross_state_hard_evidence_flags(kg):
    sigs = [Signal(SignalKind.FAMILY, "RedRAT"), Signal(SignalKind.FAMILY, "BlueWiper")]
    a = assess("x", sigs, kg)
    assert any("multiple actors" in f for f in a.false_flag_indicators)
    assert a.confidence in (Confidence.LOW, Confidence.INSUFFICIENT)


def test_same_state_overlap_is_note_not_flag(attack):
    camps = [Campaign("a", "a", "A1", [Signal(SignalKind.FAMILY, "x1")]),
             Campaign("b", "b", "A2", [Signal(SignalKind.FAMILY, "x2")])]
    kg = KnowledgeGraph(camps, {"A1": {"country": "KP"}, "A2": {"country": "KP"}})
    a = assess("x", [Signal(SignalKind.FAMILY, "x1"), Signal(SignalKind.FAMILY, "x2")], kg)
    assert not a.false_flag_indicators and a.notes


def test_tooling_vs_tradecraft_divergence(kg):
    # Blue's exclusive wiper, but Red's rare tradecraft (hijack / tool theft pattern)
    sigs = [Signal(SignalKind.FAMILY, "BlueWiper"), Signal(SignalKind.TTP, "T1001"),
            Signal(SignalKind.TTP, "T1002"), Signal(SignalKind.TTP, "T1059.001")]
    a = assess("x", sigs, kg)
    assert any("tradecraft" in f for f in a.false_flag_indicators)


def test_ablation_configs_run(kg):
    sigs = [Signal(SignalKind.FAMILY, "RedRAT"), Signal(SignalKind.TTP, "T1001")]
    for cfg in (EngineConfig(specificity=False), EngineConfig(ttp_similarity=False),
                EngineConfig(false_flag=False)):
        assert assess("x", sigs, kg, config=cfg).hypotheses


# --- benchmark harness --------------------------------------------------------

def test_campaign_cases_and_evaluate(attack, kg):
    cases = bench.attack_campaign_cases(attack, attack)
    assert {c.case_id for c in cases} == {"C9001", "C9002"}
    for m in bench.METHODS:
        s = bench.evaluate(m, cases, kg)
        assert s["n"] == 2 and 0 <= s["top1"] <= 1 and s["brier"] >= 0
    s = bench.evaluate("dragnet", cases, kg)
    assert s["top1"] == 1.0


def test_temporal_filter(attack):
    cases = bench.attack_campaign_cases(attack, attack, created_after="2020-01-01")
    assert [c.case_id for c in cases] == ["C9001"]


def test_rank_credit_ties():
    assert bench._rank_credit({"a": 1, "b": 1}, {"a"}, 1) == 0.5
    assert bench._rank_credit({"a": 2, "b": 1}, {"b"}, 1) == 0.0
    assert bench._rank_credit({"a": 1, "b": 1, "c": 1}, {"c"}, 3) == 1.0
    assert bench._rr({"a": 1, "b": 1}, {"a"}) == pytest.approx(0.75)


def test_ece_and_brier():
    assert bench.ece([(1.0, True), (1.0, True)]) == 0.0
    assert bench.ece([(0.9, False)]) == pytest.approx(0.9)
    assert bench._brier({"a": 1.0}, {"a"}) == 0.0
    assert bench._brier({"a": 1.0}, set()) == 2.0    # truth UNKNOWN, all mass on 'a'


def test_false_flag_planting(attack, kg):
    cases = bench.attack_campaign_cases(attack, attack)
    planted = bench.plant_false_flags(cases, kg, level=2)
    assert planted and all(c.meta["decoy"] not in c.truth for c in planted)
    assert all(any(s.source == "planted" for s in c.signals) for c in planted)
    kg_rh = bench.reference_rich_headers(kg)
    r = bench.evaluate_false_flag("dragnet", planted, kg_rh)
    assert r["confident_decoy"] == 0.0 and r["flagged"] > 0


# --- curated cases ------------------------------------------------------------

def test_real_case_fixtures_are_well_formed():
    cases = load_real_cases(ROOT / "fixtures" / "real_cases")
    assert len(cases) >= 6
    ids = {c.case_id for c in cases}
    assert {"olympic_destroyer_2018", "wannacry_2017", "turla_oilrig_2019"} <= ids
    for c in cases:
        assert c.expected in ("attribute", "withhold", "abstain")
        assert c.references, c.case_id
        for add in c.kg_additions:
            assert add.get("source"), c.case_id
    od = next(c for c in cases if c.case_id == "olympic_destroyer_2018")
    assert od.false_flag and "S0365" in od.novel_software


def test_addition_campaigns_resolve_actor(attack):
    cases = load_real_cases(ROOT / "fixtures" / "real_cases")
    wc = next(c for c in cases if c.case_id == "wannacry_2017")
    camps = addition_campaigns(wc, attack)
    assert camps and camps[0].actor == "G0032"  # unresolved in mini bundle -> id kept


def test_json_io_roundtrip_of_bazaar_csv_header_only(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("# only comments\n")
    assert list(iter_bazaar(p)) == []
    assert io  # keep import used
