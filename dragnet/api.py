"""Optional HTTP API (FastAPI). Install with `pip install -e .[api]`, run `dragnet serve`.

POST /assess   body = DRAGNET case JSON  -> assessment JSON (same as `assess --format json`);
               `?format=stix` returns a STIX 2.1 bundle instead
GET  /actors   -> actors in the loaded knowledge graph with sponsor state
GET  /health
The API is meant for a lab / analyst workstation: bind to localhost (the default).

Limits: request bodies over ``MAX_BODY_BYTES`` get 413; cases over the ingest limits
(:mod:`dragnet.ingest`) get 422. Requests whose ``Host`` header is not in ``allowed_hosts``
get 400 (DNS-rebinding protection for the unauthenticated localhost API).
"""
from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .ach import assess
from .graph import KnowledgeGraph
from .ingest import IngestError, build_case
from .report import to_dict
from .stix import to_stix

MAX_BODY_BYTES = 1 << 20
DEFAULT_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]", "testserver")


class BodyLimit:
    """ASGI middleware: 413 when Content-Length or the streamed body exceeds ``max_bytes``."""

    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES):
        self.app, self.max_bytes = app, max_bytes

    async def _reject(self, send) -> None:
        body = json.dumps({"detail": f"request body larger than {self.max_bytes} bytes"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k == b"content-length" and (not v.isdigit() or int(v) > self.max_bytes):
                return await self._reject(send)
        seen = 0
        started = False

        async def guarded_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_bytes:
                    raise _TooLarge
            return msg

        async def tracking_send(msg):
            nonlocal started
            started = started or msg["type"] == "http.response.start"
            await send(msg)

        try:
            await self.app(scope, guarded_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send)


class _TooLarge(Exception):
    pass


def create_app(kg_path: str | Path, allowed_hosts: tuple[str, ...] | list[str] | None = None):
    """Build the FastAPI app around the knowledge graph at ``kg_path``."""
    try:
        from fastapi import FastAPI, HTTPException
        from starlette.middleware.trustedhost import TrustedHostMiddleware
    except ImportError as e:  # pragma: no cover - optional dependency
        raise SystemExit('FastAPI is not installed: pip install -e ".[api]"') from e

    kg = KnowledgeGraph.load(kg_path)
    app = FastAPI(title="DRAGNET", version=__version__,
                  description="Evidence-to-actor attribution with ACH and false-flag reasoning")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts or DEFAULT_HOSTS))

    app.add_middleware(BodyLimit, max_bytes=MAX_BODY_BYTES)

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
