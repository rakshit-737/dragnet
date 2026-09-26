"""Optional HTTP API (FastAPI). Install with `pip install -e .[api]`, run `dragnet serve`.

POST /assess   body = DRAGNET case JSON  -> assessment JSON (same as `assess --format json`);
               `?format=stix` returns a STIX 2.1 bundle instead
GET  /actors   -> actors in the loaded knowledge graph with sponsor state
GET  /health
The API is meant for a lab / analyst workstation: bind to localhost (the default).
"""
from __future__ import annotations

from pathlib import Path

from . import __version__
from .ach import assess
from .graph import KnowledgeGraph
from .ingest import IngestError, build_case
from .report import to_dict
from .stix import to_stix


def create_app(kg_path: str | Path):
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError as e:  # pragma: no cover - optional dependency
        raise SystemExit("FastAPI is not installed: pip install -e .[api]") from e

    kg = KnowledgeGraph.load(kg_path)
    app = FastAPI(title="DRAGNET", version=__version__,
                  description="Evidence-to-actor attribution with ACH and false-flag reasoning")

    @app.get("/health")
    def health():
        return {"status": "ok", "actors": len(kg.actors), "kg": kg.meta}

    @app.get("/actors")
    def actors():
        return [{"name": a, **{k: v for k, v in kg.actor_meta.get(a, {}).items()
                               if k in ("attack_id", "country")}} for a in kg.actors]

    @app.post("/assess")
    def assess_case(case: dict, format: str = "json"):
        try:
            case_id, _items, signals, custody = build_case(case)
        except IngestError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        if format not in ("json", "stix"):
            raise HTTPException(status_code=422, detail="format must be json or stix")
        a = assess(case_id, signals, kg, custody=custody)
        return to_stix(a) if format == "stix" else to_dict(a)

    return app
