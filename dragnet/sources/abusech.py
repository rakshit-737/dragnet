"""abuse.ch metadata loaders (ThreatFox IOCs, MalwareBazaar sample metadata).

Only metadata rows are read - hashes, imphash, family label, IOC value. DRAGNET never
fetches or handles a sample binary.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class ThreatFoxIOC:
    value: str
    ioc_type: str          # ip:port | domain | url | md5_hash | sha256_hash ...
    malware: str           # malpedia-style id, e.g. win.cobalt_strike
    malware_printable: str
    first_seen: str
    confidence: int


@dataclass(frozen=True)
class BazaarSample:
    first_seen: str
    sha256: str
    file_type: str
    signature: str         # family label (MalwareBazaar "signature")
    imphash: str
    tlsh: str


def _open_member(path: Path) -> io.TextIOBase:
    if path.suffix == ".zip":
        zf = zipfile.ZipFile(path)
        name = zf.namelist()[0]
        return io.TextIOWrapper(zf.open(name), encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


def iter_threatfox(path: str | Path) -> Iterator[ThreatFoxIOC]:
    with _open_member(Path(path)) as f:
        data = json.load(f)
    for recs in data.values():
        for r in recs:
            yield ThreatFoxIOC(
                str(r.get("ioc_value", "")), str(r.get("ioc_type", "")),
                str(r.get("malware") or ""), str(r.get("malware_printable") or ""),
                str(r.get("first_seen_utc") or ""), int(r.get("confidence_level") or 0))


def iter_bazaar(path: str | Path) -> Iterator[BazaarSample]:
    """Stream the MalwareBazaar CSV export (comment lines start with '#')."""
    with _open_member(Path(path)) as f:
        rows = csv.reader((ln for ln in f if not ln.startswith("#")), skipinitialspace=True)
        for r in rows:
            if len(r) < 14:
                continue
            na = lambda v: "" if v.strip() in ("n/a", "") else v.strip()  # noqa: E731
            yield BazaarSample(r[0], r[1].lower(), na(r[6]), na(r[8]), na(r[11]).lower(), na(r[13]))
