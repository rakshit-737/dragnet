"""Round-3 case-set builders on tiny in-test fixtures (no downloads)."""
import json

from dragnet import bench
from dragnet.casesets import actor_resolver, malpedia_cases, pick_release
from dragnet.graph import KnowledgeGraph
from dragnet.models import Campaign, Signal, SignalKind
from dragnet.sources.abusech import BazaarSample, ThreatFoxIOC
from dragnet.sources.attack import AttackData, load_attack
from dragnet.sources.malpedia import MalpediaFamily, family_name_index, load_actor_synonyms, load_families
from dragnet.sources.misp import ThreatActor


def _grp(sid, gid, name, aliases=()):
    return {"type": "intrusion-set", "id": sid, "name": name, "aliases": [name, *aliases],
            "external_references": [{"source_name": "mitre-attack", "external_id": gid}]}


def _bundle(objs, name, version="19.2", modified="2026-01-01T00:00:00Z"):
    return {"type": "bundle", "objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--" + name, "name": name,
         "x_mitre_version": version, "modified": modified}, *objs]}


def test_multi_domain_union_and_revoked_resolution(tmp_path):
    ent = _bundle([_grp("intrusion-set--a", "G0001", "Alpha", ["APT-A"]),
                   {"type": "intrusion-set", "id": "intrusion-set--old", "name": "Old", "revoked": True},
                   {"type": "relationship", "id": "relationship--r", "relationship_type": "revoked-by",
                    "source_ref": "intrusion-set--old", "target_ref": "intrusion-set--a"}],
                  "Enterprise ATT&CK")
    ics = _bundle([_grp("intrusion-set--b", "G0002", "Beta")], "ICS ATT&CK")
    (tmp_path / "e.json").write_text(json.dumps(ent))
    (tmp_path / "i.json").write_text(json.dumps(ics))
    a = load_attack(tmp_path / "e.json", tmp_path / "i.json")
    assert {g.name for g in a.groups.values()} == {"Alpha", "Beta"}
    assert a.domains == ["Enterprise ATT&CK", "ICS ATT&CK"]
    assert a.resolve_group("intrusion-set--old") == "intrusion-set--a"
    assert a.resolve_group("intrusion-set--missing") is None


def _attack(groups):
    from dragnet.sources.attack import AttackObject
    g = {f"g{i}": AttackObject(f"g{i}", f"G{i:04d}", n, "intrusion-set", list(al))
         for i, (n, al) in enumerate(groups)}
    return AttackData("19.2", "2026", g, {}, {}, {}, {}, {})


def test_actor_resolver_drops_ambiguous_names():
    attack = _attack([("APT28", ["Fancy Bear"]), ("APT29", ["Cozy Bear"])])
    misp = [ThreatActor("Sofacy", ["Fancy Bear", "STRONTIUM"]),
            ThreatActor("Bad cluster", ["Fancy Bear", "Cozy Bear", "Shared"])]   # spans two groups
    r = actor_resolver(attack, misp, {"Strontium": ["Pawn Storm"]})
    assert r["sofacy"] == "APT28" and r["strontium"] == "APT28" and r["cozybear"] == "APT29"
    assert "shared" not in r and "badcluster" not in r


def test_pick_release_is_strictly_before():
    rels = [AttackData(v, d, {}, {}, {}, {}, {}, {}) for v, d in
            [("12.1", "2022-10-27"), ("13.1", "2023-05-09"), ("14.1", "2023-11-14")]]
    assert pick_release(rels, "2023-06-01").version == "13.1"
    assert pick_release(rels, "2023-05-09") .version == "12.1"
    assert pick_release(rels, "2020-01-01") is None


def test_malpedia_loaders_and_name_index(tmp_path):
    (tmp_path / "f.json").write_text(json.dumps({
        "win.alpha": {"common_name": "AlphaRAT", "alt_names": ["Shared"], "attribution": ["APT28"]},
        "win.beta": {"common_name": "Beta", "alt_names": ["Shared"], "attribution": []}}))
    (tmp_path / "a.json").write_text(json.dumps({"APT28": {"meta": {"synonyms": ["Sofacy"]}}}))
    fams = load_families(tmp_path / "f.json")
    assert fams["win.alpha"].attribution == ["APT28"]
    idx = family_name_index(fams)
    assert idx["alpharat"] == "win.alpha" and "shared" not in idx
    assert load_actor_synonyms(tmp_path / "a.json") == {"APT28": ["Sofacy"]}


def test_malpedia_cases_post_cutoff_and_deterministic():
    fams = {"win.alpha": MalpediaFamily("win.alpha", "AlphaRAT", [], ["Sofacy"]),
            "win.multi": MalpediaFamily("win.multi", "Multi", [], ["X", "Y"])}
    tf = [ThreatFoxIOC(f"10.0.0.{i}:443", "ip:port", "win.alpha", "AlphaRAT", f"2024-0{1 + i % 5}-01", 100)
          for i in range(30)]
    tf.append(ThreatFoxIOC("old.example", "domain", "win.alpha", "AlphaRAT", "2023-01-01", 100))
    bz = [BazaarSample("2024-02-01", f"{i:064x}", "exe", "AlphaRAT", f"imp{i}", "") for i in range(15)]
    kw = {"cutoff": "2024-01-01", "with_family_name": False, "max_iocs": 5, "max_samples": 3}
    a = malpedia_cases(fams, {"sofacy": "APT28"}, tf, bz, seed=1, **kw)
    b = malpedia_cases(fams, {"sofacy": "APT28"}, tf, bz, seed=1, **kw)
    c = malpedia_cases(fams, {"sofacy": "APT28"}, tf, bz, seed=2, **kw)
    assert [s.key for s in a[0].signals] == [s.key for s in b[0].signals]
    assert [s.key for s in a[0].signals] != [s.key for s in c[0].signals]
    assert len(a) == 1 and a[0].truth == {"APT28"}             # multi-attribution family skipped
    assert all(s.value != "old.example" for s in a[0].signals)  # pre-cutoff IOC excluded
    assert a[0].meta["n_iocs"] == 5 and a[0].meta["n_samples"] == 3


def test_ttp_bayes_prefers_specific_profile():
    kg = KnowledgeGraph([Campaign("c1", "c", "Narrow", [Signal(SignalKind.TTP, "T1001")]),
                         Campaign("c2", "c", "Broad", [Signal(SignalKind.TTP, t) for t in
                                                       ("T1001", "T1002", "T1003", "T1004")])])
    p = bench.ttp_bayes([Signal(SignalKind.TTP, "T1001")], kg)
    assert p.scores["Narrow"] == 1.0 and p.scores["Broad"] == 0.25
