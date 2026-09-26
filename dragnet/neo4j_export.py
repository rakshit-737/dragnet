"""Neo4j adapter: export a knowledge graph (and optionally one assessment) as Cypher.

Dependency-free: writes a `.cypher` script you load with
    cypher-shell -u neo4j -p <pw> -f dragnet.cypher
Schema:
    (:Actor {name, country, attack_id})<-[:ATTRIBUTED_TO]-(:Campaign {id, name})
    (:Campaign)-[:HAS_SIGNAL]->(:Signal {key, kind, value})
    (:Case {id, verdict, confidence})-[:OBSERVED]->(:Signal)
"""
from __future__ import annotations

import json

from .graph import KnowledgeGraph
from .models import Assessment


def _q(v) -> str:
    return json.dumps("" if v is None else str(v))


def to_cypher(kg: KnowledgeGraph, assessment: Assessment | None = None,
              signals=None) -> str:
    L = ["// DRAGNET knowledge graph export",
         "CREATE CONSTRAINT actor_name IF NOT EXISTS FOR (a:Actor) REQUIRE a.name IS UNIQUE;",
         "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE;",
         "CREATE CONSTRAINT signal_key IF NOT EXISTS FOR (s:Signal) REQUIRE s.key IS UNIQUE;"]
    for a in kg.actors:
        m = kg.actor_meta.get(a, {})
        L.append(f"MERGE (a:Actor {{name: {_q(a)}}}) SET a.country = {_q(m.get('country'))}, "
                 f"a.attack_id = {_q(m.get('attack_id'))};")
    for c in kg.campaigns.values():
        L.append(f"MERGE (c:Campaign {{id: {_q(c.id)}}}) SET c.name = {_q(c.name)} "
                 f"WITH c MATCH (a:Actor {{name: {_q(c.actor)}}}) MERGE (c)-[:ATTRIBUTED_TO]->(a);")
        for s in c.signals:
            key = f"{s.key[0]}:{s.key[1]}"
            L.append(f"MERGE (s:Signal {{key: {_q(key)}}}) SET s.kind = {_q(s.kind.value)}, "
                     f"s.value = {_q(s.value)} WITH s MATCH (c:Campaign {{id: {_q(c.id)}}}) "
                     f"MERGE (c)-[:HAS_SIGNAL]->(s);")
    if assessment is not None:
        L.append(f"MERGE (k:Case {{id: {_q(assessment.case_id)}}}) SET k.verdict = "
                 f"{_q(assessment.leading)}, k.confidence = {_q(assessment.confidence.value)};")
        for s in signals or []:
            key = f"{s.key[0]}:{s.key[1]}"
            L.append(f"MERGE (s:Signal {{key: {_q(key)}}}) SET s.kind = {_q(s.kind.value)}, "
                     f"s.value = {_q(s.value)} WITH s MATCH (k:Case {{id: {_q(assessment.case_id)}}}) "
                     f"MERGE (k)-[:OBSERVED]->(s);")
    return "\n".join(L) + "\n"
