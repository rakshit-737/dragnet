"""Evidence ingestion: synthetic forensic artifacts + static malware features -> signals.

No real malware is ever loaded; malware evidence is a JSON *feature record*
(as a static-triage tool like VITRINE would emit), never an executable.
"""
from __future__ import annotations

import json
from pathlib import Path

from .custody import CustodyLog, canonical_hash
from .models import EvidenceItem, Signal, SignalKind

_FORENSIC_MAP = {
    "network_connections": SignalKind.IP,
    "dns_queries": SignalKind.DOMAIN,
    "dropped_file_hashes": SignalKind.FILE_HASH,
    "ttps": SignalKind.TTP,
    "mutexes": SignalKind.MUTEX,
    "victimology": SignalKind.VICTIMOLOGY,
}
_MALWARE_MAP = {
    "sha256": SignalKind.FILE_HASH,
    "imphash": SignalKind.IMPHASH,
    "code_reuse": SignalKind.CODE_REUSE,
    "family": SignalKind.FAMILY,
    "ttps": SignalKind.TTP,
    "rich_header": SignalKind.RICH_HEADER,
    "language_artifacts": SignalKind.LANGUAGE,
    "c2": SignalKind.DOMAIN,
    "c2_ips": SignalKind.IP,
    "mutexes": SignalKind.MUTEX,
}


class IngestError(ValueError):
    pass


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (str, int, float)):
        return [str(v)]
    if isinstance(v, list):
        return [str(x) for x in v if x not in (None, "")]
    raise IngestError(f"unsupported field type: {type(v).__name__}")


def extract_signals(item: EvidenceItem) -> list[Signal]:
    mapping = {"forensic": _FORENSIC_MAP, "malware": _MALWARE_MAP}.get(item.kind)
    if mapping is None:
        raise IngestError(f"unknown evidence kind: {item.kind!r}")
    out: list[Signal] = []
    seen = set()
    for fname, kind in mapping.items():
        for v in _as_list(item.content.get(fname)):
            s = Signal(kind, v.strip(), item.id)
            if s.key not in seen:
                seen.add(s.key)
                out.append(s)
    return out


def load_case(path: str | Path, custody: CustodyLog | None = None):
    """Load a case JSON: {"case_id", "evidence": [{"id","kind","content"}]}."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return build_case(data, custody)


def build_case(data: dict, custody: CustodyLog | None = None):
    custody = custody if custody is not None else CustodyLog()
    if "case_id" not in data or not isinstance(data.get("evidence"), list):
        raise IngestError("case needs 'case_id' and 'evidence' list")
    items, signals = [], []
    for raw in data["evidence"]:
        if not isinstance(raw, dict) or "id" not in raw or "kind" not in raw:
            raise IngestError("evidence item needs 'id' and 'kind'")
        item = EvidenceItem(raw["id"], raw["kind"], raw.get("content", {}))
        item.sha256 = canonical_hash(item.content)
        custody.record("ingest", item.id, item.sha256)
        items.append(item)
        signals.extend(extract_signals(item))
    return data["case_id"], items, signals, custody
