#!/usr/bin/env python3
"""Download the public datasets DRAGNET builds its knowledge graph and benchmarks from.

Metadata only: STIX/JSON/CSV intelligence records. No malware sample is ever
downloaded - MalwareBazaar and ThreatFox are fetched as their public *metadata*
exports (hashes, imphash, family label, IOC values), never as binaries.

Pinned sources (ATT&CK, MISP galaxy, APTnotes) are verified against a hard-coded
SHA-256. Live feeds (abuse.ch) change daily, so their SHA-256 is recorded in
``MANIFEST.json`` next to the data and in ``data/MANIFEST.json`` in the repo, which
documents the exact snapshot the published benchmark numbers were produced from.

Usage:
    python scripts/download_data.py                # everything (~300 MB)
    python scripts/download_data.py --skip-bazaar  # skip the 220 MB MalwareBazaar dump
    python scripts/download_data.py --only attack_19_2 misp_threat_actor
    DRAGNET_DATA=/path/to/dir python scripts/download_data.py
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import sys
import time
import urllib.request
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from dragnet.paths import data_dir

ATTACK = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
MISP_SHA = "e9e867fe5a5e94be813540af9e227ac84c8d60ad"
MISP = f"https://raw.githubusercontent.com/MISP/misp-galaxy/{MISP_SHA}/clusters"
APTNOTES_SHA = "8595fbdee6747be9e9f730fd0bacd247157314df"

# name -> (url, filename, pinned?, licence); pinned sources are checked against PINNED_SHA256
SOURCES: dict[str, tuple[str, str, bool, str]] = {
    "attack_19_2": (f"{ATTACK}/enterprise-attack-19.2.json", "enterprise-attack-19.2.json",
                    True, "MITRE ATT&CK Terms of Use (royalty-free, attribution)"),
    "attack_10_1": (f"{ATTACK}/enterprise-attack-10.1.json", "enterprise-attack-10.1.json",
                    True, "MITRE ATT&CK Terms of Use (royalty-free, attribution)"),
    "misp_threat_actor": (f"{MISP}/threat-actor.json", "misp-threat-actor.json",
                          True, "CC0-1.0 / BSD-2-Clause (MISP galaxy)"),
    "misp_malpedia": (f"{MISP}/malpedia.json", "misp-malpedia.json",
                      True, "CC BY-NC-SA 3.0 (Malpedia via MISP galaxy)"),
    "aptnotes": (f"https://raw.githubusercontent.com/aptnotes/data/{APTNOTES_SHA}/APTnotes.csv",
                 "APTnotes.csv", True, "APTnotes (public report index; reports (c) authors)"),
    "threatfox_full": ("https://threatfox.abuse.ch/export/json/full/", "threatfox-full.json.zip",
                       False, "CC0 (abuse.ch ThreatFox)"),
    "bazaar_full": ("https://bazaar.abuse.ch/export/csv/full/", "bazaar-full.csv.zip",
                    False, "CC0 (abuse.ch MalwareBazaar, metadata only)"),
}

# Verified 2026-09-26; a mismatch aborts the run (the upstream file changed or was tampered with).
PINNED_SHA256 = {
    "attack_19_2": "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
    "attack_10_1": "0a999035f26f4326ad670ec51727014fd42c21fca4bda4be784ac6ad0510fcb6",
    "misp_threat_actor": "9caebf1f7b9680ba0f1c6a0b0c18e5d250acc74fe2bdc9b127a54dc1759cba6f",
    "misp_malpedia": "1a1523635946c2d25572024b2a89553db11b6a296337cd1bcfd17223b24142b4",
    "aptnotes": "dac4579a78ad0ad644d6f57670f31ac54f0424b3ab2619c8119d8f65e48adf0b",
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _valid(path: Path, suffix: str) -> bool:
    """Structural check before a download is accepted (JSON parses, zip CRCs match)."""
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(path) as z:
                return z.testzip() is None
        if suffix == ".json":
            with path.open(encoding="utf-8") as f:
                json.load(f)
        return True
    except (OSError, ValueError, zipfile.BadZipFile, zlib.error):
        return False


def fetch(url: str, dest: Path, retries: int = 5) -> None:
    """Download with gzip transfer-encoding for text sources (ATT&CK JSON is ~10x smaller on
    the wire). Every attempt restarts from zero: the abuse.ch exports are regenerated daily, so
    resuming a partial file across a regeneration silently produces a corrupt archive."""
    tmp = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, retries + 1):
        headers = {"User-Agent": "dragnet-dataset-fetcher/1.0", "Accept-Encoding": "gzip"}
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:
                src = gzip.GzipFile(fileobj=r) if r.headers.get("Content-Encoding") == "gzip" else r
                with tmp.open("wb") as f:
                    shutil.copyfileobj(src, f, 1 << 20)
            if not _valid(tmp, dest.suffix):
                raise OSError("downloaded file failed structural validation")
            tmp.replace(dest)
            return
        except OSError as e:  # URLError / timeouts are OSErrors
            print(f"  attempt {attempt} failed: {e}", file=sys.stderr)
            time.sleep(min(30, 2 * attempt))
    raise SystemExit(f"could not download {url}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", default=None, help="target directory (default: $DRAGNET_DATA)")
    ap.add_argument("--only", nargs="*", choices=sorted(SOURCES), help="subset of sources")
    ap.add_argument("--skip-bazaar", action="store_true", help="skip the 220 MB MalwareBazaar dump")
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    args = ap.parse_args(argv)

    dest = Path(args.dest) if args.dest else data_dir()
    dest.mkdir(parents=True, exist_ok=True)
    manifest_path = dest / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

    names = args.only or list(SOURCES)
    if args.skip_bazaar and "bazaar_full" in names:
        names.remove("bazaar_full")
    for name in names:
        url, fname, pinned, licence = SOURCES[name]
        path = dest / fname
        if args.force or not path.exists():
            print(f"[get] {name}: {url}")
            fetch(url, path)
        else:
            print(f"[have] {name}: {path}")
        digest = sha256_of(path)
        expected = PINNED_SHA256.get(name)
        if pinned and expected and digest != expected:
            raise SystemExit(f"checksum mismatch for {name}: {digest} != {expected}")
        prev = manifest.get(name, {})
        manifest[name] = {
            "url": url, "file": fname, "sha256": digest, "bytes": path.stat().st_size,
            "pinned": bool(pinned), "licence": licence,
            "retrieved_utc": prev.get("retrieved_utc") if prev.get("sha256") == digest
            else datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        print(f"       sha256={digest}  {path.stat().st_size / 1e6:.1f} MB")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    repo_manifest = REPO / "data" / "MANIFEST.json"
    repo_manifest.parent.mkdir(exist_ok=True)
    repo_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"manifest -> {manifest_path} and {repo_manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
