"""MISP galaxy loaders (threat-actor + malpedia clusters).

Used for (a) alias resolution - "Hidden Cobra", "Fancy Bear", "Voodoo Bear" resolve to
ATT&CK groups - and (b) suspected sponsor state, which drives the language/locale
signals and the cross-state false-flag rule.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# ISO-3166 alpha-2 of the suspected sponsor -> dominant locale tag a planted
# language artifact would carry. Deliberately coarse: language is a weak signal.
COUNTRY_LANG = {
    "RU": "ru", "CN": "zh", "KP": "ko", "KR": "ko", "IR": "fa", "VN": "vi", "PK": "ur",
    "IN": "hi", "US": "en", "GB": "en", "IL": "he", "TR": "tr", "LB": "ar", "PS": "ar",
    "AE": "ar", "SY": "ar", "UA": "uk", "BY": "ru", "KZ": "ru", "ES": "es", "FR": "fr",
    "DE": "de", "IT": "it", "NG": "en", "BR": "pt", "TW": "zh",
}

STATE_TO_ISO = {
    "russian federation": "RU", "russia": "RU", "china": "CN",
    "korea (democratic people's republic of)": "KP", "north korea": "KP",
    "iran (islamic republic of)": "IR", "iran": "IR", "viet nam": "VN", "vietnam": "VN",
    "pakistan": "PK", "india": "IN", "united states": "US", "israel": "IL",
    "turkey": "TR", "lebanon": "LB", "united arab emirates": "AE", "belarus": "BY",
    "korea (republic of)": "KR", "south korea": "KR", "ukraine": "UA",
}


def norm(name: str) -> str:
    """Canonical alias key: lowercase alphanumerics only ('APT 28' == 'apt-28')."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


@dataclass
class ThreatActor:
    name: str
    synonyms: list[str] = field(default_factory=list)
    country: str | None = None        # ISO alpha-2 of suspected sponsor / origin

    @property
    def names(self) -> list[str]:
        return [self.name, *self.synonyms]


def load_threat_actors(path: str | Path) -> list[ThreatActor]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for v in data.get("values", []):
        meta = v.get("meta") or {}
        country = meta.get("country")
        if isinstance(country, list):
            country = country[0] if country else None
        if not country:
            sponsor = meta.get("cfr-suspected-state-sponsor") or ""
            country = STATE_TO_ISO.get(str(sponsor).strip().lower())
        out.append(ThreatActor(v["value"], list(meta.get("synonyms") or []),
                               country.upper() if isinstance(country, str) else None))
    return out


def load_malpedia_families(path: str | Path) -> dict[str, list[str]]:
    """family name -> synonyms (for resolving free-text family names to ATT&CK software)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {v["value"]: list((v.get("meta") or {}).get("synonyms") or [])
            for v in data.get("values", [])}


def alias_index(actors: list[ThreatActor]) -> dict[str, ThreatActor]:
    idx: dict[str, ThreatActor] = {}
    for a in actors:
        for n in a.names:
            idx.setdefault(norm(n), a)
    return idx
