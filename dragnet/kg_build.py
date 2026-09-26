"""Build a DRAGNET knowledge graph from real public CTI.

Layers (each optional, each traceable to its source):
  1. MITRE ATT&CK groups         -> one "profile" campaign per group
                                    (techniques -> ttp, malware -> family, tool -> tool)
  2. MITRE ATT&CK campaigns      -> attributed campaigns (C0xxx -> group)
  3. MISP threat-actor galaxy    -> aliases + suspected sponsor state -> language signal
  4. abuse.ch ThreatFox          -> IOCs (ip/domain) of actor-specific families
  5. abuse.ch MalwareBazaar      -> imphashes of actor-specific families
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable

from .graph import KnowledgeGraph
from .models import Campaign, Signal, SignalKind
from .sources.abusech import BazaarSample, ThreatFoxIOC
from .sources.attack import AttackData
from .sources.misp import COUNTRY_LANG, ThreatActor, alias_index, norm

# The .NET CLR stub imphash and friends are shared by thousands of unrelated
# families; any imphash seen in more families than this is dropped as non-genetic.
MAX_FAMILIES_PER_IMPHASH = 2


def software_aliases(attack: AttackData,
                     malpedia: dict[str, list[str]] | None = None) -> dict[str, list[str]]:
    """software stix id -> all known names (ATT&CK name + aliases + Malpedia synonyms)."""
    out = {sid: list(dict.fromkeys([sw.name, *sw.aliases])) for sid, sw in attack.software.items()}
    if not malpedia:
        return out
    by_norm: dict[str, str] = {}
    for sid, names in out.items():
        for n in names:
            by_norm.setdefault(norm(n), sid)
    for fam, syns in malpedia.items():
        names = [fam, *syns]
        sid = next((by_norm[norm(n)] for n in names if norm(n) in by_norm), None)
        if sid:
            out[sid] = list(dict.fromkeys(out[sid] + names))
    return out


def software_signals(attack: AttackData, sw_ids: Iterable[str],
                     aliases: dict[str, list[str]] | None = None) -> list[Signal]:
    out = []
    for sid in sw_ids:
        sw = attack.software[sid]
        kind = SignalKind.FAMILY if sw.type == "malware" else SignalKind.TOOL
        names = aliases[sid] if aliases else [sw.name, *sw.aliases]
        for n in dict.fromkeys(names):
            out.append(Signal(kind, n))
    return out


def technique_signals(attack: AttackData, sid: str) -> list[Signal]:
    return [Signal(SignalKind.TTP, t) for t in sorted(attack.techniques_of(sid))]


def group_countries(attack: AttackData, misp: list[ThreatActor] | None) -> dict[str, str]:
    """ATT&CK group stix id -> sponsor ISO code, via MISP alias matching."""
    if not misp:
        return {}
    idx = alias_index(misp)
    out = {}
    for gid, g in attack.groups.items():
        for n in [g.attack_id, g.name, *g.aliases]:
            ta = idx.get(norm(n))
            if ta and ta.country:
                out[gid] = ta.country
                break
    return out


def build_from_attack(attack: AttackData, *, misp: list[ThreatActor] | None = None,
                      include_campaigns: bool = False,
                      exclude_campaigns: set[str] = frozenset(),
                      exclude_software: set[str] = frozenset(),
                      malpedia: dict[str, list[str]] | None = None,
                      language_signals: bool = True) -> KnowledgeGraph:
    """exclude_software: ATT&CK software ids (S0366) hidden from the graph - used to
    simulate time-of-incident knowledge when a case introduced a brand-new family."""
    countries = group_countries(attack, misp)
    sw_alias = software_aliases(attack, malpedia)
    hidden = {sid for sid, sw in attack.software.items() if sw.attack_id in exclude_software}
    misp_idx = alias_index(misp) if misp else {}
    camps: list[Campaign] = []
    actor_meta: dict[str, dict] = {}
    for gid, g in sorted(attack.groups.items(), key=lambda kv: kv[1].attack_id):
        sigs = technique_signals(attack, gid) + software_signals(
            attack, attack.software_of(gid) - hidden, sw_alias)
        cc = countries.get(gid)
        if language_signals and cc in COUNTRY_LANG:
            sigs.append(Signal(SignalKind.LANGUAGE, f"lang:{COUNTRY_LANG[cc]}"))
        camps.append(Campaign(f"{g.attack_id}-profile", f"{g.name} (ATT&CK group profile)",
                              g.name, sigs))
        aliases = list(dict.fromkeys([*g.aliases] + [
            s for n in [g.name, *g.aliases] if norm(n) in misp_idx
            for s in misp_idx[norm(n)].names]))
        actor_meta[g.name] = {"attack_id": g.attack_id, "stix_id": gid, "country": cc,
                              "aliases": [a for a in aliases if a != g.name]}
    if include_campaigns:
        for cid, gid in attack.attributed.items():
            c = attack.campaigns[cid]
            if c.attack_id in exclude_campaigns or gid not in attack.groups:
                continue
            sigs = technique_signals(attack, cid) + software_signals(
                attack, attack.software_of(cid) - hidden, sw_alias)
            camps.append(Campaign(c.attack_id, c.name, attack.groups[gid].name, sigs))
    meta = {"source": f"MITRE ATT&CK Enterprise v{attack.version}",
            "include_campaigns": include_campaigns, "misp": bool(misp)}
    return KnowledgeGraph(camps, actor_meta, meta)


def family_actor_map(attack: AttackData, max_actors: int = 3,
                     malpedia: dict[str, list[str]] | None = None) -> dict[str, set[str]]:
    """normalised family name/alias -> actor names, for actor-specific malware only."""
    out: dict[str, set[str]] = {}
    sw_alias = software_aliases(attack, malpedia)
    for sid, gids in attack.software_attribution().items():
        sw = attack.software[sid]
        if sw.type != "malware" or len(gids) > max_actors:
            continue
        actors = {attack.groups[g].name for g in gids}
        for n in sw_alias[sid]:
            out.setdefault(norm(n), set()).update(actors)
    return out


def enrich_threatfox(kg: KnowledgeGraph, attack: AttackData, iocs: Iterable[ThreatFoxIOC],
                     max_actors: int = 3, min_confidence: int = 50,
                     malpedia: dict[str, list[str]] | None = None) -> tuple[KnowledgeGraph, dict]:
    fam = family_actor_map(attack, max_actors, malpedia)
    per: dict[tuple[str, str], set[Signal]] = defaultdict(set)
    hits = Counter()
    for i in iocs:
        if i.confidence < min_confidence:
            continue
        actors = fam.get(norm(i.malware_printable)) or fam.get(norm(i.malware.split(".", 1)[-1]))
        if not actors:
            continue
        if i.ioc_type == "ip:port":
            sig = Signal(SignalKind.IP, i.value.rsplit(":", 1)[0])
        elif i.ioc_type == "domain":
            sig = Signal(SignalKind.DOMAIN, i.value)
        elif i.ioc_type in ("sha256_hash", "md5_hash"):
            sig = Signal(SignalKind.FILE_HASH, i.value)
        else:
            continue
        hits[i.malware_printable] += 1
        for a in actors:
            per[(a, i.malware_printable)].add(sig)
    camps = list(kg.campaigns.values())
    for (actor, family), sigs in sorted(per.items()):
        camps.append(Campaign(f"TF-{norm(family)}-{norm(actor)}",
                              f"ThreatFox IOCs for {family}", actor, sorted(sigs, key=str)))
    meta = dict(kg.meta, threatfox_families=dict(hits))
    return KnowledgeGraph(camps, kg.actor_meta, meta), dict(hits)


def imphash_family_index(samples: Iterable[BazaarSample]) -> dict[str, Counter]:
    """imphash -> Counter(family) over all labelled samples (for collision filtering)."""
    idx: dict[str, Counter] = defaultdict(Counter)
    for s in samples:
        if s.imphash and s.signature:
            idx[s.imphash][norm(s.signature)] += 1
    return idx


def enrich_bazaar(kg: KnowledgeGraph, attack: AttackData, samples: Iterable[BazaarSample],
                  max_actors: int = 3, before: str | None = None,
                  global_index: dict[str, Counter] | None = None,
                  malpedia: dict[str, list[str]] | None = None) -> tuple[KnowledgeGraph, dict]:
    """Add imphash signals of actor-specific families (optionally only samples seen < before)."""
    fam = family_actor_map(attack, max_actors, malpedia)
    per: dict[tuple[str, str], set[Signal]] = defaultdict(set)
    hits = Counter()
    for s in samples:
        if not s.imphash or not s.signature or (before and s.first_seen >= before):
            continue
        actors = fam.get(norm(s.signature))
        if not actors:
            continue
        if global_index is not None and len(global_index.get(s.imphash, ())) > MAX_FAMILIES_PER_IMPHASH:
            continue
        hits[s.signature] += 1
        for a in actors:
            per[(a, s.signature)].add(Signal(SignalKind.IMPHASH, s.imphash))
    camps = list(kg.campaigns.values())
    for (actor, family), sigs in sorted(per.items()):
        camps.append(Campaign(f"MB-{norm(family)}-{norm(actor)}",
                              f"MalwareBazaar imphashes for {family}", actor,
                              sorted(sigs, key=str)))
    meta = dict(kg.meta, bazaar_families=dict(hits))
    return KnowledgeGraph(camps, kg.actor_meta, meta), dict(hits)
