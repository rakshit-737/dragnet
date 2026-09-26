"""Adapters from sibling-tool exports to a DRAGNET case file.

* REVENANT (forensic timeline reconstruction) ``export.to_json`` -> one ``forensic`` item:
  ATT&CK techniques from stories and events, IPs / domains from event objects
  (``ip:1.2.3.4:443``, ``domain:evil.example``, ``dns:...``), tool names from process images.
  Tampering (anti-forensics) indicators are carried as analyst context, not as signals.
* VITRINE (static malware triage) ``TriageResult.to_dict`` -> one ``malware`` item:
  sha256, family, ATT&CK capabilities and, when present, imphash / Rich header / C2.

Both adapters only read JSON produced by those tools; nothing is executed.
"""
from __future__ import annotations

import ipaddress
import re

_TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_PRIVATE_OK = False
# RFC 1918 / RFC 4193 internal ranges (documentation ranges such as TEST-NET are kept so
# fixtures can use them)
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                "100.64.0.0/10", "fc00::/7")]


def _ip(v: str) -> str | None:
    host = v.rsplit(":", 1)[0] if v.count(":") == 1 else v
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not _PRIVATE_OK and (any(ip in n for n in _INTERNAL if n.version == ip.version)
                            or ip.is_loopback or ip.is_link_local or ip.is_unspecified):
        return None                         # internal addresses carry no attribution signal
    return str(ip)


def _object_signals(obj: str, ips: set, domains: set) -> None:
    kind, _, rest = obj.partition(":")
    kind = kind.lower()
    if kind == "ip":
        if (ip := _ip(rest)):
            ips.add(ip)
    elif kind in ("domain", "dns", "url"):
        host = re.sub(r"^[a-z]+://", "", rest).split("/")[0].split(":")[0].lower()
        if host and "." in host and not _ip(host):
            domains.add(host)


def from_revenant(doc: dict, item_id: str = "revenant") -> tuple[dict, list[str]]:
    """REVENANT JSON export -> (forensic evidence item, analyst notes)."""
    ttps, ips, domains, tools = set(), set(), set(), set()
    for s in doc.get("stories", []):
        ttps.update(t for t in s.get("techniques", []) if _TID.match(str(t)))
    for e in doc.get("events", []):
        ttps.update(t for t in e.get("techniques", []) if _TID.match(str(t)))
        for field in ("object", "actor"):
            v = str(e.get(field, ""))
            _object_signals(v, ips, domains)
            if v.lower().startswith("process:"):
                img = re.split(r"[:/\\]", v)[-1].lower()
                if img.endswith(".exe"):
                    tools.add(img)
    notes = [f"REVENANT anti-forensics indicator: {i.get('indicator')} - {i.get('detail', '')}"
             for i in doc.get("indicators", []) if isinstance(i, dict)]
    content = {"ttps": sorted(ttps), "network_connections": sorted(ips), "dns_queries": sorted(domains)}
    # process images are only kept when they are not stock Windows binaries
    stock = {"cmd.exe", "powershell.exe", "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
             "rundll32.exe", "wmiprvse.exe", "conhost.exe", "winlogon.exe", "csrss.exe", "taskhostw.exe"}
    extra = sorted(t for t in tools if t not in stock)
    if extra:
        content["tools"] = [t.removesuffix(".exe") for t in extra]
    return {"id": item_id, "kind": "forensic", "content": content}, notes


def from_vitrine(doc: dict, item_id: str | None = None) -> dict:
    """VITRINE triage JSON -> malware evidence item (feature record, never a binary)."""
    content: dict = {}
    for k in ("sha256", "imphash", "rich_header", "c2", "c2_ips", "mutexes", "code_reuse"):
        if doc.get(k):
            content[k] = doc[k]
    if doc.get("family"):
        content["family"] = doc["family"]
    caps = [c.get("attack_id") for c in doc.get("capabilities", []) if isinstance(c, dict)]
    content["ttps"] = sorted({c for c in caps if c and _TID.match(c)})
    return {"id": item_id or f"vitrine-{str(doc.get('sha256', 'sample'))[:12]}", "kind": "malware",
            "content": content}


def build_case_doc(case_id: str, revenant: list[dict] = (), vitrine: list[dict] = ()) -> dict:
    evidence, notes = [], []
    for i, d in enumerate(revenant):
        item, n = from_revenant(d, f"revenant-{i}")
        evidence.append(item)
        notes += n
    evidence += [from_vitrine(d) for d in vitrine]
    out = {"case_id": case_id, "evidence": evidence}
    if notes:
        out["analyst_context"] = notes
    return out
