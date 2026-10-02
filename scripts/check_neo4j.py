"""Load a `dragnet export-cypher` script into a local Neo4j and check node/edge counts (CI only).

Usage: python scripts/check_neo4j.py kg.cypher   (Neo4j on bolt://127.0.0.1:7687, started by CI)
"""
import sys
from pathlib import Path

from neo4j import GraphDatabase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dragnet.graph import KnowledgeGraph
from dragnet.paths import FIXTURES


def main(path: str) -> int:
    text = "\n".join(ln for ln in Path(path).read_text(encoding="utf-8").splitlines()
                     if not ln.lstrip().startswith("//"))
    stmts = [s.strip() for s in text.split(";\n") if s.strip()]
    kg = KnowledgeGraph.load(FIXTURES / "campaigns.json")
    drv = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "ci-only-password"))
    with drv.session() as s:
        for st in stmts:
            s.run(st.rstrip(";")).consume()
        actors = s.run("MATCH (a:Actor) RETURN count(a) AS n").single()["n"]
        camps = s.run("MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(:Actor) RETURN count(c) AS n").single()["n"]
        sigs = s.run("MATCH (s:Signal) RETURN count(s) AS n").single()["n"]
        obs = s.run("MATCH ()-[r:OBSERVED]->() RETURN count(r) AS n").single()["n"]
    drv.close()
    print(f"statements={len(stmts)} actors={actors} campaigns={camps} signals={sigs} observed={obs}")
    want_sigs = len({s.key for c in kg.campaigns.values() for s in c.signals})
    ok = actors >= len(kg.actors) and camps == len(kg.campaigns) and sigs >= want_sigs and obs > 0
    print("OK" if ok else f"MISMATCH: expected actors>={len(kg.actors)} campaigns={len(kg.campaigns)} "
          f"signals>={want_sigs} observed>0")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
