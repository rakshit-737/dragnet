"""STIX 2.1 export of an attribution assessment (dependency-free).

Produces a bundle with: an ``identity`` (DRAGNET), a ``report`` wrapping everything, the
incident as a ``campaign``, the leading ``intrusion-set`` (only when an actor is named), an ``attributed-to`` relationship
carrying the graded confidence, a ``note`` with the case's signals, the ACH matrix and
false-flag indicators, and the ATT&CK
``attack-pattern`` references for observed techniques.

IDs are deterministic UUIDv5 values so re-exporting the same assessment yields the same bundle.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from .models import Assessment

_NS = uuid.UUID("6f1c1d7e-4b1a-5c7e-9d7a-2d7a6e0a1b11")
# STIX confidence scale (0-100); mapped from DRAGNET's grade, see STIX 2.1 appendix A
GRADE_TO_STIX = {"HIGH": 85, "MEDIUM": 50, "LOW": 15, "INSUFFICIENT": 0}


def _id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, '|'.join((kind,) + parts))}"


def to_stix(a: Assessment, created: str | None = None) -> dict:
    ts = created or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ident = _id("identity", "dragnet")
    common = {"spec_version": "2.1", "created": ts, "modified": ts, "created_by_ref": ident}
    objs: list[dict] = [{"type": "identity", "id": ident, "spec_version": "2.1", "created": ts,
                         "modified": ts, "name": "DRAGNET", "identity_class": "system"}]
    refs: list[str] = []

    signals = sorted(a.matrix)
    ttps = sorted({s.split(":", 1)[1] for s in signals if s.startswith("ttp:")})
    for t in ttps:
        o = {"type": "attack-pattern", "id": _id("attack-pattern", t), **common, "name": t,
             "external_references": [{"source_name": "mitre-attack", "external_id": t,
                                      "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}]}
        objs.append(o)
        refs.append(o["id"])

    camp = {"type": "campaign", "id": _id("campaign", a.case_id), **common, "name": a.case_id,
            "description": "Incident under assessment."}
    objs.append(camp)
    refs.append(camp["id"])
    if a.leading:
        iset = {"type": "intrusion-set", "id": _id("intrusion-set", a.leading), **common, "name": a.leading}
        rel = {"type": "relationship", "id": _id("relationship", a.case_id, a.leading), **common,
               "relationship_type": "attributed-to", "source_ref": camp["id"],
               "target_ref": iset["id"], "confidence": GRADE_TO_STIX[a.confidence.value],
               "description": f"DRAGNET ACH assessment: {a.confidence.value} confidence."}
        objs += [iset, rel]
        refs += [iset["id"], rel["id"]]

    lines = [f"Assessment: {a.leading or 'insufficient for attribution'} ({a.confidence.value})",
             "False-flag indicators: " + ("; ".join(a.false_flag_indicators) or "none"),
             "Raise confidence: " + "; ".join(a.raise_confidence),
             "Lower confidence: " + "; ".join(a.lower_confidence),
             "ACH matrix (signal: hypothesis=C/I/N):"]
    lines += [f"  {sig}: " + ", ".join(f"{h}={v}" for h, v in row.items()) for sig, row in a.matrix.items()]
    note = {"type": "note", "id": _id("note", a.case_id), **common, "abstract": "DRAGNET ACH matrix",
            "content": "\n".join(lines), "object_refs": [camp["id"]],
            "x_dragnet_custody_head": a.custody[-1]["entry_hash"] if a.custody else None,
            "x_dragnet_signals": signals}
    objs.append(note)
    refs.append(note["id"])

    report = {"type": "report", "id": _id("report", a.case_id), **common,
              "name": f"DRAGNET attribution assessment: {a.case_id}", "published": ts,
              "report_types": ["threat-actor", "attack-pattern"],
              "confidence": GRADE_TO_STIX[a.confidence.value],
              "description": "Analytic judgment, not proof; must be reviewed by a qualified analyst.",
              "object_refs": refs or [ident]}
    objs.append(report)
    return {"type": "bundle", "id": _id("bundle", a.case_id, ts), "objects": objs}


def to_stix_json(a: Assessment, created: str | None = None) -> str:
    return json.dumps(to_stix(a, created), indent=2)
