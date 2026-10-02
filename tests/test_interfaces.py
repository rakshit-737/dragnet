"""CLI, Neo4j export, API and (optional) real-data tests."""
import json
from pathlib import Path

import pytest

from dragnet.cli import main
from dragnet.graph import KnowledgeGraph
from dragnet.neo4j_export import to_cypher
from dragnet.paths import data_dir

ROOT = Path(__file__).resolve().parent.parent
KG = ROOT / "dragnet" / "data" / "campaigns.json"
CASES = ROOT / "dragnet" / "data" / "cases"
MINI = ROOT / "fixtures" / "mini"


def test_export_cypher(tmp_path):
    out = tmp_path / "g.cypher"
    assert main(["export-cypher", "--kg", str(KG), "--case", str(CASES / "wannacry_like.json"),
                 "-o", str(out)]) == 0
    text = out.read_text()
    assert "MERGE (a:Actor {name: \"LAZARUS_SIM\"})" in text
    assert ":OBSERVED" in text and "CREATE CONSTRAINT" in text


def test_cypher_escapes_quotes():
    from dragnet.models import Campaign, Signal, SignalKind
    kg = KnowledgeGraph([Campaign("c", 'O"Brien', "A", [Signal(SignalKind.FAMILY, 'x"y')])])
    assert '\\"' in to_cypher(kg)


def test_build_kg_from_mini(tmp_path):
    # the CLI expects the ATT&CK file name pattern; stage the mini fixtures accordingly
    for src, dst in (("attack-mini.json", "enterprise-attack-0.1.json"),
                     ("misp-threat-actor-mini.json", "misp-threat-actor.json"),
                     ("misp-malpedia-mini.json", "misp-malpedia.json")):
        (tmp_path / dst).write_text((MINI / src).read_text())
    out = tmp_path / "kg.json"
    assert main(["build-kg", "--attack-version", "0.1", "--data", str(tmp_path),
                 "--with-campaigns", "-o", str(out)]) == 0
    kg = KnowledgeGraph.load(out)
    assert "Red Group" in kg.actors and "C9001" in kg.campaigns


def test_build_kg_missing_data(tmp_path, capsys):
    assert main(["build-kg", "--data", str(tmp_path)]) == 2
    assert "not found" in capsys.readouterr().err


def test_cli_errors_are_one_line(tmp_path, capsys):
    assert main(["assess", str(tmp_path / "nope.json")]) == 2
    assert main(["assess", str(CASES / "wannacry_like.json"), "--kg", str(tmp_path / "kg.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(["assess", str(bad)]) == 2
    bad.write_text('{"case_id": 5, "evidence": []}')
    assert main(["assess", str(bad)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.count("dragnet:") == 4


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and "dragnet" in capsys.readouterr().out


def test_api_limits():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from dragnet.api import MAX_BODY_BYTES, create_app
    client = TestClient(create_app(KG))
    big = {"case_id": "x", "evidence": [{"id": "e", "kind": "forensic", "content": {"ips": ["1" * 400] * 3000}}]}
    assert client.post("/assess", json=big).status_code == 413
    many = {"case_id": "x", "evidence": [{"id": f"e{i}", "kind": "forensic", "content": {}} for i in range(600)]}
    assert len(json.dumps(many)) < MAX_BODY_BYTES
    assert client.post("/assess", json=many).status_code == 422
    assert client.post("/assess", json={"case_id": "x", "evidence": [
        {"id": "e", "kind": "forensic", "content": ["a"]}]}).status_code == 422
    assert client.post("/assess?format=stix", json={"case_id": 123, "evidence": []}).status_code == 422
    assert client.get("/health", headers={"host": "rebind.attacker.example"}).status_code == 400


def test_api_assess():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from dragnet.api import create_app
    client = TestClient(create_app(KG))
    assert client.get("/health").json()["status"] == "ok"
    case = json.loads((CASES / "wannacry_like.json").read_text())
    r = client.post("/assess", json=case)
    assert r.status_code == 200 and r.json()["leading"] == "LAZARUS_SIM"
    assert client.post("/assess", json={"evidence": []}).status_code == 422


# ---------------------------------------------------------------- real data
REAL = data_dir() / "enterprise-attack-19.2.json"


@pytest.mark.realdata
@pytest.mark.skipif(not REAL.exists(), reason="real ATT&CK data not downloaded")
def test_realdata_case_studies_behave(capsys):
    assert main(["case-study", "--format", "summary"]) == 0
    out = capsys.readouterr().out
    od = next(ln for ln in out.splitlines() if ln.startswith("olympic_destroyer_2018"))
    assert "HIGH" not in od and "MEDIUM" not in od
    wc = next(ln for ln in out.splitlines() if ln.startswith("wannacry_2017"))
    assert "Lazarus Group" in wc.split("truth=")[0]


def test_api_assess_stix():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from dragnet.api import create_app
    client = TestClient(create_app(KG))
    case = json.loads((CASES / "wannacry_like.json").read_text())
    r = client.post("/assess?format=stix", json=case)
    assert r.status_code == 200 and r.json()["type"] == "bundle"
    assert client.post("/assess?format=xml", json=case).status_code == 422
