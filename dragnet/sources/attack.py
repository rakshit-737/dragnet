"""MITRE ATT&CK (STIX 2.1 bundle) loader.

Extracts the parts of the ATT&CK graph DRAGNET needs:
  * intrusion-sets (groups)   -> actors
  * malware / tool objects    -> software families (with aliases)
  * attack-patterns           -> technique ids (T1234 / T1234.001)
  * campaigns                 -> documented, attributed intrusion episodes
  * relationships             -> uses (group/campaign/software -> technique/software)
                                 attributed-to (campaign -> group)
Revoked and deprecated objects are dropped.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AttackObject:
    stix_id: str
    attack_id: str
    name: str
    type: str
    aliases: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    created: str | None = None


@dataclass
class AttackData:
    version: str
    released: str                            # collection "modified" timestamp
    groups: dict[str, AttackObject]          # stix id -> group
    software: dict[str, AttackObject]        # stix id -> malware/tool
    techniques: dict[str, AttackObject]      # stix id -> attack-pattern
    campaigns: dict[str, AttackObject]       # stix id -> campaign
    uses: dict[str, set[str]]                # source stix id -> target stix ids
    attributed: dict[str, str]               # campaign stix id -> group stix id

    # --- convenience views -------------------------------------------------
    def techniques_of(self, sid: str) -> set[str]:
        return {self.techniques[t].attack_id for t in self.uses.get(sid, ()) if t in self.techniques}

    def software_of(self, sid: str) -> set[str]:
        return {t for t in self.uses.get(sid, ()) if t in self.software}

    def software_attribution(self) -> dict[str, set[str]]:
        """software stix id -> group stix ids that use it (directly or via attributed campaigns)."""
        out: dict[str, set[str]] = defaultdict(set)
        for gid in self.groups:
            for s in self.software_of(gid):
                out[s].add(gid)
        for cid, gid in self.attributed.items():
            for s in self.software_of(cid):
                out[s].add(gid)
        return dict(out)


def _ext_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def _live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def load_attack(path: str | Path) -> AttackData:
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    objs = bundle["objects"]
    coll = next((o for o in objs if o.get("type") == "x-mitre-collection"), {})
    version, released = coll.get("x_mitre_version", ""), coll.get("modified", "")
    groups, software, techniques, campaigns = {}, {}, {}, {}
    for o in objs:
        t = o.get("type")
        if t not in ("intrusion-set", "malware", "tool", "attack-pattern", "campaign") or not _live(o):
            continue
        aliases = list(o.get("aliases") or o.get("x_mitre_aliases") or [])
        ao = AttackObject(o["id"], _ext_id(o), o.get("name", ""), t, aliases,
                          o.get("first_seen"), o.get("last_seen"), o.get("created"))
        {"intrusion-set": groups, "malware": software, "tool": software,
         "attack-pattern": techniques, "campaign": campaigns}[t][o["id"]] = ao

    uses: dict[str, set[str]] = defaultdict(set)
    attributed: dict[str, str] = {}
    live = set(groups) | set(software) | set(techniques) | set(campaigns)
    for o in objs:
        if o.get("type") != "relationship" or not _live(o):
            continue
        src, dst, rt = o.get("source_ref"), o.get("target_ref"), o.get("relationship_type")
        if src not in live or dst not in live:
            continue
        if rt == "uses":
            uses[src].add(dst)
        elif rt == "attributed-to" and src in campaigns and dst in groups:
            attributed[src] = dst
    return AttackData(version, released, groups, software, techniques, campaigns, dict(uses), attributed)
