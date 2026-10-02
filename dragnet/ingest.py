"""Evidence ingestion: forensic artifacts + static malware features -> signals.

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
    "tools": SignalKind.TOOL,
    "language_artifacts": SignalKind.LANGUAGE,
}
_MALWARE_MAP = {
    "sha256": SignalKind.FILE_HASH,
    "imphash": SignalKind.IMPHASH,
    "tlsh": SignalKind.TLSH,
    "code_reuse": SignalKind.CODE_REUSE,
    "family": SignalKind.FAMILY,
    "ttps": SignalKind.TTP,
    "rich_header": SignalKind.RICH_HEADER,
    "language_artifacts": SignalKind.LANGUAGE,
    "c2": SignalKind.DOMAIN,
    "c2_ips": SignalKind.IP,
    "mutexes": SignalKind.MUTEX,
    "tools": SignalKind.TOOL,
}


class IngestError(ValueError):
    pass


# Input limits (also enforced by the HTTP API): a case is an analyst's evidence abstraction,
# not a bulk feed. Larger inputs are rejected rather than silently truncated.
MAX_EVIDENCE_ITEMS = 500
MAX_VALUES_PER_FIELD = 1000
MAX_VALUE_LENGTH = 512
MAX_SIGNALS = 5000
MAX_ID_LENGTH = 128


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (str, int, float)):
        vals = [str(v)]
    elif isinstance(v, list):
        if len(v) > MAX_VALUES_PER_FIELD:
            raise IngestError(f"field has {len(v)} values (max {MAX_VALUES_PER_FIELD})")
        if any(isinstance(x, (dict, list)) for x in v):
            raise IngestError("field values must be strings or numbers")
        vals = [str(x) for x in v if x not in (None, "")]
    else:
        raise IngestError(f"unsupported field type: {type(v).__name__}")
    if any(len(x) > MAX_VALUE_LENGTH for x in vals):
        raise IngestError(f"value longer than {MAX_VALUE_LENGTH} characters")
    return vals


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
    """Validate a case document and turn it into (case_id, items, signals, custody).

    Raises :class:`IngestError` on malformed input or when a size limit is exceeded."""
    custody = custody if custody is not None else CustodyLog()
    if not isinstance(data, dict) or "case_id" not in data or not isinstance(data.get("evidence"), list):
        raise IngestError("case needs 'case_id' and 'evidence' list")
    if not isinstance(data["case_id"], str) or not 0 < len(data["case_id"]) <= MAX_ID_LENGTH:
        raise IngestError(f"case_id must be a non-empty string of at most {MAX_ID_LENGTH} characters")
    if len(data["evidence"]) > MAX_EVIDENCE_ITEMS:
        raise IngestError(f"case has {len(data['evidence'])} evidence items (max {MAX_EVIDENCE_ITEMS})")
    items, signals = [], []
    for raw in data["evidence"]:
        if not isinstance(raw, dict) or "id" not in raw or "kind" not in raw:
            raise IngestError("evidence item needs 'id' and 'kind'")
        if not isinstance(raw["id"], str) or not 0 < len(raw["id"]) <= MAX_ID_LENGTH:
            raise IngestError(f"evidence id must be a string of at most {MAX_ID_LENGTH} characters")
        content = raw.get("content", {})
        if not isinstance(content, dict):
            raise IngestError("evidence 'content' must be an object")
        item = EvidenceItem(raw["id"], raw["kind"], content)
        item.sha256 = canonical_hash(item.content)
        custody.record("ingest", item.id, item.sha256)
        items.append(item)
        signals.extend(extract_signals(item))
        if len(signals) > MAX_SIGNALS:
            raise IngestError(f"case yields more than {MAX_SIGNALS} signals")
    return data["case_id"], items, signals, custody
