# Datasets

All data is public threat-intelligence *metadata*. No malware sample is downloaded, stored or executed.
Files land in `$DRAGNET_DATA` (default `../../datasets/dragnet` next to the repo, else `data/raw/`),
never in git. `python scripts/download_data.py` fetches everything and writes `$DRAGNET_DATA/MANIFEST.json`
(SHA-256, size, retrieval time). The committed `data/MANIFEST.json` records the exact snapshot the
committed results were produced from; it is only updated when `--record` is passed.

| Source | File | Size | Version / pin | Licence / terms | Used for |
|---|---|---|---|---|---|
| MITRE ATT&CK Enterprise | `enterprise-attack-19.2.json` | 54 MB | v19.2 | ATT&CK Terms of Use (royalty-free, attribution required) | actor profiles, campaigns, software, ground truth (A1, A3, C, D) |
| MITRE ATT&CK Enterprise | `enterprise-attack-10.1.json` | 31 MB | v10.1 (Nov 2021) | as above | temporal hold-out profiles (A2) |
| MISP galaxy threat-actor | `misp-threat-actor.json` | 1.4 MB | commit `e9e867f` | CC0 / BSD-2-Clause | aliases, suspected sponsor state |
| MISP galaxy malpedia | `misp-malpedia.json` | 3.8 MB | commit `e9e867f` | CC BY-NC-SA 3.0 (Malpedia) | family synonym resolution |
| APTnotes | `APTnotes.csv` | 0.15 MB | commit `8595fbd` | index metadata; reports (c) their authors | per-actor reporting depth (F) |
| abuse.ch ThreatFox | `threatfox-full.json.zip` | 3.8 MB | live export (see manifest) | CC0 | IOC layer, IOC shelf-life (E1) |
| abuse.ch MalwareBazaar | `bazaar-full.csv.zip` | 223 MB | live export (see manifest) | CC0; metadata only | imphash genetics layer (E2) |

## Citations

- MITRE ATT&CK, "Enterprise ATT&CK", The MITRE Corporation, https://attack.mitre.org (STIX data: https://github.com/mitre-attack/attack-stix-data).
- MISP Project, "MISP galaxy", https://github.com/MISP/misp-galaxy.
- Fraunhofer FKIE, "Malpedia", https://malpedia.caad.fkie.fraunhofer.de (via the MISP galaxy cluster).
- APTnotes, https://github.com/aptnotes/data.
- abuse.ch, "ThreatFox" https://threatfox.abuse.ch and "MalwareBazaar" https://bazaar.abuse.ch.

## Curated real cases

`fixtures/real_cases/*.json` are small hand-curated evidence abstractions of documented incidents.
Values that are widely published (WannaCry kill-switch domain, sample SHA-256s, ATT&CK technique
lists) are used verbatim. Where the public evidence is a relationship rather than a value (e.g. "the
Rich header is byte-identical to a Lazarus sample", "code overlaps with Contopee"), the case uses a
descriptive token (`rh:bluenoroff-sample-copy`) and the matching `kg_additions` entry cites the report
that established the link. The tokens do not reproduce the original artifacts.
