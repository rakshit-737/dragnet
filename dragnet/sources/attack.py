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
    domains: list[str] = field(default_factory=list)   # x_mitre_domains


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
    revoked_by: dict[str, str] = field(default_factory=dict)   # revoked stix id -> successor
    domains: list[str] = field(default_factory=list)            # e.g. enterprise-attack, ics-attack
    # citations (external_references source_name, 'mitre-*' excluded) of each 'uses' edge and of
    # each object; used for leave-report-out protocols and per-report cases
    uses_refs: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict)
    obj_refs: dict[str, frozenset[str]] = field(default_factory=dict)
    attributed_refs: dict[str, frozenset[str]] = field(default_factory=dict)

    def resolve_group(self, gid: str) -> str | None:
        """Follow revoked-by links (groups merged in later versions) to a live group id."""
        seen = set()
        while gid not in self.groups and gid in self.revoked_by and gid not in seen:
            seen.add(gid)
            gid = self.revoked_by[gid]
        return gid if gid in self.groups else None

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


def _refs(obj: dict) -> frozenset[str]:
    return frozenset(r["source_name"] for r in obj.get("external_references", [])
                     if r.get("source_name") and not r["source_name"].startswith("mitre-")
                     and r["source_name"] != "capec")


def _live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def load_attack(path: str | Path | list, *extra: str | Path) -> AttackData:
    """Load one ATT&CK bundle, or merge several domains (enterprise + ics + mobile of the
    same release) into one graph: ``load_attack(ent, ics, mobile)``. Objects shared between
    domains (groups, some software) have the same STIX id, so the union is well defined."""
    paths = [*(path if isinstance(path, list) else [path]), *extra]
    objs: list[dict] = []
    colls = []
    for p in paths:
        bundle = json.loads(Path(p).read_text(encoding="utf-8"))
        objs.extend(bundle["objects"])
        colls.append(next((o for o in bundle["objects"] if o.get("type") == "x-mitre-collection"), {}))
    coll = colls[0]
    version, released = coll.get("x_mitre_version", ""), coll.get("modified", "")
    domains = [c.get("name", "") for c in colls]
    groups, software, techniques, campaigns = {}, {}, {}, {}
    obj_refs: dict[str, frozenset[str]] = {}
    for o in objs:
        t = o.get("type")
        if t not in ("intrusion-set", "malware", "tool", "attack-pattern", "campaign") or not _live(o):
            continue
        aliases = list(o.get("aliases") or o.get("x_mitre_aliases") or [])
        ao = AttackObject(o["id"], _ext_id(o), o.get("name", ""), t, aliases,
                          o.get("first_seen"), o.get("last_seen"), o.get("created"),
                          list(o.get("x_mitre_domains") or []))
        {"intrusion-set": groups, "malware": software, "tool": software,
         "attack-pattern": techniques, "campaign": campaigns}[t][o["id"]] = ao
        obj_refs[o["id"]] = _refs(o)

    uses: dict[str, set[str]] = defaultdict(set)
    attributed: dict[str, str] = {}
    uses_refs: dict[tuple[str, str], frozenset[str]] = {}
    attributed_refs: dict[str, frozenset[str]] = {}
    revoked_by: dict[str, str] = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            revoked_by[o["source_ref"]] = o["target_ref"]
    live = set(groups) | set(software) | set(techniques) | set(campaigns)
    for o in objs:
        if o.get("type") != "relationship" or not _live(o):
            continue
        src, dst, rt = o.get("source_ref"), o.get("target_ref"), o.get("relationship_type")
        if src not in live or dst not in live:
            continue
        if rt == "uses":
            uses[src].add(dst)
            uses_refs[(src, dst)] = uses_refs.get((src, dst), frozenset()) | _refs(o)
        elif rt == "attributed-to" and src in campaigns and dst in groups:
            attributed[src] = dst
            attributed_refs[src] = _refs(o)
    return AttackData(version, released, groups, software, techniques, campaigns, dict(uses), attributed,
                      revoked_by, domains, uses_refs, obj_refs, attributed_refs)
