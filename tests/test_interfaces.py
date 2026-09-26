"""CLI, Neo4j export, API and (optional) real-data tests."""
import json
from pathlib import Path

import pytest

from dragnet.cli import main
from dragnet.graph import KnowledgeGraph
from dragnet.neo4j_export import to_cypher
from dragnet.paths import data_dir

ROOT = Path(__file__).resolve().parent.parent
KG = ROOT / "fixtures" / "campaigns.json"
CASES = ROOT / "fixtures" / "cases"
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


def test_build_kg_missing_data(tmp_path):
    with pytest.raises(SystemExit):
        main(["build-kg", "--data", str(tmp_path)])


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
