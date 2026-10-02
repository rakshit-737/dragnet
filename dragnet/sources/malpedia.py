"""Malpedia API exports (``/api/get/families`` and ``/api/get/actors``), metadata only.

Malpedia (Fraunhofer FKIE; Plohmann et al., "Malpedia: A Collaborative Effort to Inventorize
the Malware Landscape", Botconf 2017) curates, per malware family, an ``attribution`` list of
actors with references. DRAGNET uses that list as a *documented label* for cases built from
abuse.ch metadata - a label source independent of MITRE ATT&CK.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .misp import norm


@dataclass
class MalpediaFamily:
    fid: str                       # e.g. win.wannacryptor
    common_name: str
    alt_names: list[str] = field(default_factory=list)
    attribution: list[str] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        short = self.fid.split(".", 1)[-1]
        return list(dict.fromkeys([self.common_name, short, *self.alt_names]))


def load_families(path: str | Path) -> dict[str, MalpediaFamily]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {fid: MalpediaFamily(fid, v.get("common_name") or fid.split(".", 1)[-1],
                                list(v.get("alt_names") or []), list(v.get("attribution") or []))
            for fid, v in data.items()}


def load_actor_synonyms(path: str | Path) -> dict[str, list[str]]:
    """Malpedia actor name -> synonyms (MISP-galaxy style ``meta.synonyms``)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: list((v.get("meta") or {}).get("synonyms") or []) for k, v in data.items()}


def family_name_index(fams: dict[str, MalpediaFamily]) -> dict[str, str]:
    """normalised family name / alias -> Malpedia id; ambiguous names are dropped."""
    seen: dict[str, set[str]] = {}
    for fid, f in fams.items():
        for n in f.names:
            if len(norm(n)) >= 3:
                seen.setdefault(norm(n), set()).add(fid)
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}
