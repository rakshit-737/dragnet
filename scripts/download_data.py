"""Download the public datasets DRAGNET builds its knowledge graph and benchmarks from.

Metadata only: STIX/JSON/CSV intelligence records. No malware sample is ever
downloaded - MalwareBazaar and ThreatFox are fetched as their public *metadata*
exports (hashes, imphash, family label, IOC values), never as binaries.

Pinned sources (ATT&CK, MISP galaxy, APTnotes) are verified against a hard-coded
SHA-256. Live feeds (abuse.ch) change daily, so their SHA-256 is recorded in
``MANIFEST.json`` next to the data. ``data/MANIFEST.json`` in the repo documents the exact
snapshot the published benchmark numbers were produced from; it is only updated (merged, per
source) when ``--record`` is passed, so a partial or fresh download never overwrites it.

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

# attack-stix-data pinned by commit (master moves; release files are immutable once published)
ATTACK_SHA = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
ATTACK_ROOT = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{ATTACK_SHA}"
ATTACK = f"{ATTACK_ROOT}/enterprise-attack"
# Enterprise releases since campaigns were introduced (v12, Oct 2022): used for the union of all
# campaigns across versions (B1) and the rolling-origin temporal protocol (B2).
ATTACK_RELEASES = ["12.1", "13.1", "14.1", "15.1", "16.1", "17.1", "18.1"]
TERMS = "MITRE ATT&CK Terms of Use (royalty-free, attribution)"
MISP_SHA = "e9e867fe5a5e94be813540af9e227ac84c8d60ad"
MISP = f"https://raw.githubusercontent.com/MISP/misp-galaxy/{MISP_SHA}/clusters"
TLSH_SHA = "ebdec8fde93a4ac359437f4f3796c78d3ae433bf"
TLSH_EXP = f"https://raw.githubusercontent.com/trendmicro/tlsh/{TLSH_SHA}/Testing/exp"
APTNOTES_SHA = "8595fbdee6747be9e9f730fd0bacd247157314df"

# name -> (url, filename, pinned?, licence); pinned sources are checked against PINNED_SHA256
SOURCES: dict[str, tuple[str, str, bool, str]] = {
    "attack_19_2": (f"{ATTACK}/enterprise-attack-19.2.json", "enterprise-attack-19.2.json",
                    True, "MITRE ATT&CK Terms of Use (royalty-free, attribution)"),
    "attack_10_1": (f"{ATTACK}/enterprise-attack-10.1.json", "enterprise-attack-10.1.json",
                    True, "MITRE ATT&CK Terms of Use (royalty-free, attribution)"),
    **{f"attack_{v.replace('.', '_')}": (f"{ATTACK}/enterprise-attack-{v}.json",
                                         f"enterprise-attack-{v}.json", True, TERMS)
       for v in ATTACK_RELEASES},
    "attack_ics_19_2": (f"{ATTACK_ROOT}/ics-attack/ics-attack-19.2.json", "ics-attack-19.2.json", True, TERMS),
    "attack_mobile_19_2": (f"{ATTACK_ROOT}/mobile-attack/mobile-attack-19.2.json", "mobile-attack-19.2.json",
                           True, TERMS),
    # Malpedia API (public, no key): family -> attribution labels, actor synonyms. Live data.
    "malpedia_families": ("https://malpedia.caad.fkie.fraunhofer.de/api/get/families",
                          "malpedia-families.json", False, "CC BY-NC-SA 3.0 (Malpedia, Fraunhofer FKIE)"),
    "malpedia_actors": ("https://malpedia.caad.fkie.fraunhofer.de/api/get/actors",
                        "malpedia-actors.json", False, "CC BY-NC-SA 3.0 (Malpedia, Fraunhofer FKIE)"),
    # TLSH reference test vectors (trendmicro/tlsh, Apache-2.0) used to verify dragnet.tlsh
    "tlsh_vectors": (f"{TLSH_EXP}/example_data.128.1.len.xref.scores_EXP", "tlsh-xref-scores.txt",
                     True, "Apache-2.0"),
    "tlsh_digests": (f"{TLSH_EXP}/example_data.128.1.len.out_EXP", "tlsh-digests.txt", True, "Apache-2.0"),
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

# Verified 2026-09-26 (round-3 sources 2026-10-02, sizes cross-checked with Content-Length); a mismatch aborts the run (the upstream file changed or was tampered with).
PINNED_SHA256 = {
    "attack_19_2": "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
    "attack_10_1": "0a999035f26f4326ad670ec51727014fd42c21fca4bda4be784ac6ad0510fcb6",
    "misp_threat_actor": "9caebf1f7b9680ba0f1c6a0b0c18e5d250acc74fe2bdc9b127a54dc1759cba6f",
    "misp_malpedia": "1a1523635946c2d25572024b2a89553db11b6a296337cd1bcfd17223b24142b4",
    "attack_12_1": "e84679af4bc46bba2ba92f60182101f146d5b966898e47924de7321e6bffeaa1",
    "attack_13_1": "5ec90131dc595ef7f2dd6ae0ee24074fbd5e317ed3261f9465660e04f97d426d",
    "attack_14_1": "13af7514ad1bcb59deba6b6b46571168544bbe674eb52f41361916bb1cd9c3d6",
    "attack_15_1": "a57988bffe402bb3e19d92dbe80a12143e1970b814e013e080f9df2fa5a3f6bc",
    "attack_16_1": "8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813",
    "attack_17_1": "0d1c347a4d584cf7e11ef46556c33b7689341443bf86299188d46c307274323b",
    "attack_18_1": "f857d8f78f2f0c0b7db321a711a39fba98546c1e3076a657684850c83d0962fb",
    "attack_ics_19_2": "08b83d2cea6b6d6752468ef0e62e2ab2a53c9443ef72c439ecccb07ab9e89da9",
    "attack_mobile_19_2": "acfa5ca2d93484476f79bf38590e2b55bb675fc0ce85e76bffa0af2c82dada64",
    "tlsh_vectors": "a9c2605ce5399827d10b65c514b01bff20fab380c4844db17cb109f87c3c8bc2",
    "tlsh_digests": "776adcd5a139739d963c9f990cf2eea7b66d8a69dd318da78db234fa7c9766a5",
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
    ap.add_argument("--record", action="store_true",
                    help="also merge these checksums into the repo's data/MANIFEST.json "
                         "(do this only when re-publishing benchmark results)")
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
        if path.exists() and not args.force and not _valid(path, path.suffix):
            print(f"[bad] {name}: {path} fails validation (truncated?) - re-downloading")
            path.unlink()
        if args.force or not path.exists():
            print(f"[get] {name}: {url}")
            fetch(url, path)
        else:
            print(f"[have] {name}: {path}")
        digest = sha256_of(path)
        expected = PINNED_SHA256.get(name)
        if pinned and expected is None:
            raise SystemExit(f"no pinned sha256 for {name} (add it to PINNED_SHA256)")
        if pinned and digest != expected:
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
    print(f"manifest -> {manifest_path}")
    if args.record:
        repo_manifest = REPO / "data" / "MANIFEST.json"
        repo_manifest.parent.mkdir(exist_ok=True)
        recorded = json.loads(repo_manifest.read_text()) if repo_manifest.exists() else {}
        recorded.update({n: manifest[n] for n in names})
        repo_manifest.write_text(json.dumps(recorded, indent=2, sort_keys=True) + "\n")
        print(f"recorded -> {repo_manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
