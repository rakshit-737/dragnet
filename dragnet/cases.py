"""Curated real-world case studies with published attribution as ground truth.

A case file (dragnet/data/real_cases/*.json) contains:
  ground_truth              ATT&CK group ids accepted as correct (e.g. ["G0034"])
  false_flag                true if the incident carried documented deception
  expected                  "attribute" | "withhold" (flag / <=LOW) | "abstain"
  novel_software            ATT&CK software ids first seen in this incident; hidden
                            from the knowledge graph in "time-of-incident" mode so the
                            engine cannot simply look the answer up
  attack_software_evidence  ATT&CK software ids whose *documented* techniques stand in
                            for the malware-analysis output (VITRINE role)
  evidence                  forensic / malware evidence items (standard DRAGNET format)
  kg_additions              prior public knowledge not in ATT&CK (e.g. the Lazarus
                            Rich header Olympic Destroyer copied), each with a source
  references                public reporting the case was curated from
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .ingest import build_case
from .models import Campaign, Signal, SignalKind
from .sources.attack import AttackData


@dataclass
class RealCase:
    case_id: str
    title: str
    ground_truth: list[str]            # ATT&CK group ids
    false_flag: bool
    expected: str
    novel_software: list[str]
    signals: list[Signal]
    kg_additions: list[dict] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    basis: str = ""
    raw: dict = field(default_factory=dict)


def load_real_case(path: str | Path, attack: AttackData | None = None) -> RealCase:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data.setdefault("evidence", [])
    _, _, signals, _ = build_case({"case_id": data["case_id"], "evidence": data["evidence"]})
    if attack is not None:
        by_sid = {sw.attack_id: sid for sid, sw in attack.software.items()}
        for sw_id in data.get("attack_software_evidence", []):
            sid = by_sid.get(sw_id)
            if sid is None:
                continue
            src = f"ATT&CK:{sw_id}"
            signals += [Signal(SignalKind.TTP, t, src) for t in sorted(attack.techniques_of(sid))]
    return RealCase(data["case_id"], data.get("title", data["case_id"]),
                    list(data.get("ground_truth", [])), bool(data.get("false_flag")),
                    data.get("expected", "attribute"), list(data.get("novel_software", [])),
                    signals, list(data.get("kg_additions", [])),
                    list(data.get("references", [])), data.get("ground_truth_basis", ""), data)


def load_real_cases(folder: str | Path, attack: AttackData | None = None) -> list[RealCase]:
    return [load_real_case(p, attack) for p in sorted(Path(folder).glob("*.json"))]


def addition_campaigns(case: RealCase, attack: AttackData) -> list[Campaign]:
    """kg_additions -> campaigns attributed to the named ATT&CK group."""
    names = {g.attack_id: g.name for g in attack.groups.values()}
    out = []
    for i, add in enumerate(case.kg_additions):
        actor = names.get(add["actor"], add["actor"])
        out.append(Campaign(f"{case.case_id}-prior-{i}", add.get("name", "prior reporting"), actor,
                            [Signal(SignalKind(s["kind"]), s["value"]) for s in add["signals"]]))
    return out
