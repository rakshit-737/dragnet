"""Larger evaluation case sets built from public metadata with documented labels.

B1  every attributed MITRE ATT&CK campaign across releases v12.1 - v19.2 and across the
    Enterprise, ICS and Mobile domains (union by STIX id; the latest live copy supplies the
    evidence, revoked groups are followed to their successor).
B2  rolling-origin temporal protocol: each campaign is attributed against the newest ATT&CK
    release published *before* the campaign object was created.
B3  Malpedia-labelled abuse.ch cases: for every Malpedia family with exactly one attributed
    actor that abuse.ch observed after a cutoff, a case made only of post-cutoff metadata
    (ThreatFox IOCs, MalwareBazaar imphash + TLSH digests), label = Malpedia attribution
    resolved to an ATT&CK group through ATT&CK aliases, MISP galaxy synonyms and Malpedia
    actor synonyms. The knowledge graph is built from ATT&CK plus *pre-cutoff* abuse.ch data
    only, so labels come from a source the graph never saw.
"""
from __future__ import annotations

import random
import zlib
from collections import Counter, defaultdict
from collections.abc import Iterable

from .bench import Case, campaign_signals
from .graph import KnowledgeGraph
from .kg_build import MAX_FAMILIES_PER_IMPHASH
from .models import Campaign, Signal, SignalKind
from .sources.abusech import BazaarSample, ThreatFoxIOC
from .sources.attack import AttackData
from .sources.malpedia import MalpediaFamily, family_name_index
from .sources.misp import ThreatActor, norm
from .tlsh import TlshIndex


# ------------------------------------------------------------------ B1 / B2: ATT&CK
def campaigns_across_versions(releases: list[AttackData]) -> dict[str, tuple[AttackData, str]]:
    """campaign stix id -> (release holding its latest live copy, first release it appears in).
    ``releases`` must be ordered oldest -> newest."""
    out: dict[str, tuple[AttackData, str]] = {}
    for rel in releases:
        for cid in rel.attributed:
            first = out[cid][1] if cid in out else rel.version
            out[cid] = (rel, first)
    return out


def all_campaign_cases(union: dict[str, tuple[AttackData, str]], kg_attack: AttackData) -> list[Case]:
    out = []
    for cid, (rel, first) in union.items():
        c = rel.campaigns[cid]
        sigs = campaign_signals(rel, cid)
        if not sigs:
            continue
        gid = kg_attack.resolve_group(rel.attributed[cid])
        g = kg_attack.groups.get(gid) if gid else None
        domain = ",".join(d.replace("-attack", "") for d in c.domains) or "enterprise"
        out.append(Case(c.attack_id, c.name, sigs, {g.name} if g else set(),
                        {"group": rel.groups[rel.attributed[cid]].name, "created": c.created,
                         "first_version": first, "evidence_version": rel.version, "domain": domain,
                         "n_ttp": sum(s.kind == SignalKind.TTP for s in sigs),
                         "n_software": sum(s.kind != SignalKind.TTP for s in sigs)}))
    return sorted(out, key=lambda c: c.case_id)


def pick_release(releases: list[AttackData], created: str) -> AttackData | None:
    """Newest release whose collection timestamp precedes ``created`` (None if none does)."""
    prior = [r for r in releases if r.released and r.released < created]
    return max(prior, key=lambda r: r.released) if prior else None


# ------------------------------------------------------------------ actor resolution
def actor_resolver(attack: AttackData, misp: list[ThreatActor] | None = None,
                   malpedia_actor_syns: dict[str, list[str]] | None = None) -> dict[str, str]:
    """normalised actor name (any vendor alias) -> ATT&CK group name.

    Names are first taken from ATT&CK itself; MISP galaxy and Malpedia synonym clusters are
    then attached to a group when any member of the cluster is an ATT&CK name/alias. A name
    that would map to two different groups is dropped (ambiguity is not guessed away)."""
    cand: dict[str, set[str]] = defaultdict(set)
    base: dict[str, str] = {}
    for g in attack.groups.values():
        for n in [g.name, g.attack_id, *g.aliases]:
            if norm(n):
                cand[norm(n)].add(g.name)
                base.setdefault(norm(n), g.name)
    clusters: list[list[str]] = []
    for ta in misp or []:
        clusters.append(ta.names)
    for k, syns in (malpedia_actor_syns or {}).items():
        clusters.append([k, *syns])
    for names in clusters:
        hits = {base[norm(n)] for n in names if norm(n) in base}
        if len(hits) == 1:
            g = next(iter(hits))
            for n in names:
                if norm(n):
                    cand[norm(n)].add(g)
    return {k: next(iter(v)) for k, v in cand.items() if len(v) == 1}


# ------------------------------------------------------------------ abuse.ch -> graph layers
def tlsh_family_index(samples: Iterable[BazaarSample]) -> TlshIndex:
    """TLSH index over labelled samples; label = normalised family signature."""
    idx = TlshIndex()
    seen = set()
    for s in samples:
        if s.tlsh and s.signature and (s.tlsh, norm(s.signature)) not in seen:
            seen.add((s.tlsh, norm(s.signature)))
            idx.add(s.tlsh, norm(s.signature))
    return idx


def tlsh_collides(idx: TlshIndex, digest: str, tau: int, max_families: int = MAX_FAMILIES_PER_IMPHASH) -> bool:
    """True if the tau-neighbourhood of ``digest`` spans more than ``max_families`` families
    (a packer/installer stub, not genetics) - the fuzzy analogue of the imphash filter."""
    fams = {lab for _, lab, _ in idx.nearest(digest, k=10**9, max_dist=tau)}
    return len(fams) > max_families


def enrich_tlsh(kg: KnowledgeGraph, fam_actors: dict[str, set[str]], samples: Iterable[BazaarSample],
                global_index: TlshIndex | None = None, tau: int = 50,
                per_family_cap: int = 400) -> tuple[KnowledgeGraph, dict]:
    """Add TLSH digests of actor-specific families as fuzzy signals (collision-filtered)."""
    per: dict[tuple[str, str], set[Signal]] = defaultdict(set)
    hits: Counter = Counter()
    for s in samples:
        if not s.tlsh or not s.signature:
            continue
        actors = fam_actors.get(norm(s.signature))
        if not actors or hits[s.signature] >= per_family_cap:
            continue
        if global_index is not None and tlsh_collides(global_index, s.tlsh, tau):
            continue
        hits[s.signature] += 1
        for a in actors:
            per[(a, s.signature)].add(Signal(SignalKind.TLSH, s.tlsh))
    camps = list(kg.campaigns.values())
    for (actor, family), sigs in sorted(per.items()):
        camps.append(Campaign(f"MBT-{norm(family)}-{norm(actor)}",
                              f"MalwareBazaar TLSH digests for {family}", actor, sorted(sigs, key=str)))
    return KnowledgeGraph(camps, kg.actor_meta, dict(kg.meta, tlsh_tau=tau, tlsh_families=dict(hits))), dict(hits)


# ------------------------------------------------------------------ B3: Malpedia-labelled cases
def _ioc_signal(i: ThreatFoxIOC) -> Signal | None:
    if i.ioc_type == "ip:port":
        return Signal(SignalKind.IP, i.value.rsplit(":", 1)[0], "threatfox")
    if i.ioc_type == "domain":
        return Signal(SignalKind.DOMAIN, i.value, "threatfox")
    if i.ioc_type in ("sha256_hash", "md5_hash"):
        return Signal(SignalKind.FILE_HASH, i.value, "threatfox")
    return None


def malpedia_cases(fams: dict[str, MalpediaFamily], resolver: dict[str, str],
                   threatfox: list[ThreatFoxIOC], bazaar: list[BazaarSample], cutoff: str,
                   *, with_family_name: bool, max_iocs: int = 20, max_samples: int = 10,
                   seed: int = 0) -> list[Case]:
    """One case per single-attribution Malpedia family with post-cutoff abuse.ch metadata.

    Evidence is a deterministic random subset (seeded per family) of post-cutoff ThreatFox
    IOCs and MalwareBazaar samples (imphash + TLSH). ``with_family_name`` adds the family
    name as an analyst's classification would; without it the case is artifacts only."""
    name_idx = family_name_index(fams)
    iocs: dict[str, list[Signal]] = defaultdict(list)
    for i in threatfox:
        if i.first_seen < cutoff or i.malware not in fams:
            continue
        s = _ioc_signal(i)
        if s:
            iocs[i.malware].append(s)
    smp: dict[str, list[BazaarSample]] = defaultdict(list)
    for b in bazaar:
        if b.first_seen < cutoff or not b.signature:
            continue
        fid = name_idx.get(norm(b.signature))
        if fid and (b.imphash or b.tlsh):
            smp[fid].append(b)
    out = []
    for fid in sorted(set(iocs) | set(smp)):
        f = fams[fid]
        if len(f.attribution) != 1:
            continue
        rng = random.Random(seed * 7919 + zlib.crc32(fid.encode()))
        ii = sorted(set(iocs.get(fid, [])), key=lambda s: s.key)
        ii = rng.sample(ii, min(max_iocs, len(ii)))
        ss = sorted(smp.get(fid, []), key=lambda b: b.sha256)
        ss = rng.sample(ss, min(max_samples, len(ss)))
        sigs = list(ii)
        for b in ss:
            if b.imphash:
                sigs.append(Signal(SignalKind.IMPHASH, b.imphash, b.sha256))
            if b.tlsh:
                sigs.append(Signal(SignalKind.TLSH, b.tlsh, b.sha256))
        sigs = list({s.key: s for s in sigs}.values())
        if with_family_name:
            sigs.append(Signal(SignalKind.FAMILY, f.common_name, "analyst-classification"))
        if not sigs:
            continue
        actor = f.attribution[0]
        g = resolver.get(norm(actor))
        out.append(Case(fid, f.common_name, sigs, {g} if g else set(),
                        {"malpedia_actor": actor, "n_iocs": len(ii), "n_samples": len(ss),
                         "label_source": "Malpedia attribution"}))
    return out
