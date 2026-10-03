# Datasets

All data is public threat-intelligence *metadata*. No malware sample is downloaded, stored or executed.
Files land in `$DRAGNET_DATA` (default `../../datasets/dragnet` next to the repo, else `data/raw/`),
never in git. `python scripts/download_data.py` fetches everything (about 640 MB, the byte total of
`data/MANIFEST.json`) and writes `$DRAGNET_DATA/MANIFEST.json` (SHA-256, size, retrieval time). The
committed `data/MANIFEST.json` records the exact snapshot the committed results were produced from.

| Source | File(s) | Size | Version / pin | Licence / terms | Used for |
|---|---|---|---|---|---|
| MITRE ATT&CK Enterprise | `enterprise-attack-19.2.json` | 54 MB | v19.2, commit + SHA-256 | ATT&CK Terms of Use (royalty-free, attribution) | profiles, campaigns, software, ground truth (A1, A1-LF, A3, R, G, C, D, F) |
| MITRE ATT&CK Enterprise | `enterprise-attack-10.1.json` | 31 MB | v10.1, SHA-256 | as above | stale open-world profiles (A2) |
| MITRE ATT&CK Enterprise | `enterprise-attack-{12.1 ... 18.1}.json` | 315 MB | 7 releases, SHA-256 | as above | campaign union (B1), rolling origin (B2), v14.1 graph (B3) |
| MITRE ATT&CK ICS + Mobile | `ics-attack-19.2.json`, `mobile-attack-19.2.json` | 4.1 + 5.8 MB | v19.2, SHA-256 | as above | campaign union across domains (B1) |
| MISP galaxy threat-actor | `misp-threat-actor.json` | 1.4 MB | commit `e9e867f` + SHA-256 | CC0 / BSD-2-Clause | aliases, suspected sponsor state |
| MISP galaxy malpedia | `misp-malpedia.json` | 3.8 MB | commit `e9e867f` + SHA-256 | CC BY-NC-SA 3.0 (Malpedia) | family synonym resolution |
| Malpedia API | `malpedia-families.json`, `malpedia-actors.json` | 4.2 + 1.2 MB | live API, SHA-256 in the manifest | CC BY-NC-SA 3.0 (Fraunhofer FKIE) | B3 labels and actor synonyms |
| APTnotes | `APTnotes.csv` | 0.15 MB | commit `8595fbd` + SHA-256 | index metadata; reports (c) their authors | per-actor reporting depth (F) |
| abuse.ch ThreatFox | `threatfox-full.json.zip` | 3.9 MB | live export, SHA-256 in the manifest | CC0 | IOC layer (B3), export structure (E1) |
| abuse.ch MalwareBazaar | `bazaar-full.csv.zip` | 224 MB | live export, SHA-256 in the manifest | CC0; metadata only | imphash (E2) and TLSH (E3) genetics, B3, K |
| trendmicro/tlsh test vectors | `tlsh-digests.txt`, `tlsh-xref-scores.txt` | 0.25 MB | commit `ebdec8f` + SHA-256 | Apache-2.0 | verifies `dragnet.tlsh` against the reference implementation (tests) |
| APTMalware hash list | `aptmalware-overview.csv` | 1.0 MB | commit `d71ee9f` + SHA-256 | ODbL 1.0 | hash overlap with MalwareBazaar (K); the samples themselves are never fetched |

## Citations

- MITRE ATT&CK, "Enterprise ATT&CK", The MITRE Corporation, <https://attack.mitre.org>; STIX data:
  <https://github.com/mitre-attack/attack-stix-data>.
- MISP Project, "MISP galaxy", <https://github.com/MISP/misp-galaxy>.
- Fraunhofer FKIE, "Malpedia", <https://malpedia.caad.fkie.fraunhofer.de> (API and via the MISP galaxy cluster).
- APTnotes, <https://github.com/aptnotes/data>.
- abuse.ch, "ThreatFox" <https://threatfox.abuse.ch> and "MalwareBazaar" <https://bazaar.abuse.ch>.
- Trend Micro, "TLSH" reference implementation, <https://github.com/trendmicro/tlsh>.
- APTMalware dataset, <https://github.com/cyber-research/APTMalware>.

## Literature compared against

- K. Guru, R. J. Moss and M. J. Kochenderfer, "On Technique Identification and Threat-Actor
  Attribution using LLMs and Embedding Models", arXiv:2505.11547, 2025,
  <https://arxiv.org/abs/2505.11547> (section G: adapted protocol, not a reproduction).
- J. Oliver, C. Cheng and Y. Chen, "TLSH - A Locality Sensitive Hash", 2013 Fourth Cybercrime and
  Trustworthy Computing Workshop (CTC), pp. 7-13, doi:[10.1109/CTC.2013.9](https://doi.org/10.1109/CTC.2013.9)
  (Table II: about a 6.43% file-pair false-positive rate at distance < 100; section E3).
- T. Kida and O. Olukoya, "Nation-State Threat Actor Attribution Using Fuzzy Hashing", IEEE Access
  11:1148-1165, 2023, doi:[10.1109/ACCESS.2022.3233403](https://doi.org/10.1109/ACCESS.2022.3233403)
  (89% average accuracy over the country and APT-group tasks on APTMalware; needs the binaries, so it
  is not matched - section K counts how many of its hashes MalwareBazaar metadata knows).

## Curated real cases

`dragnet/data/real_cases/*.json` are small hand-curated evidence abstractions of documented incidents.
Values that are widely published (WannaCry kill-switch domain, sample SHA-256s, ATT&CK technique
lists) are used verbatim. Where the public evidence is a relationship rather than a value (e.g. "the
Rich header is byte-identical to a Lazarus sample", "code overlaps with Contopee"), the case uses a
descriptive token (`rh:bluenoroff-sample-copy`) and the matching `kg_additions` entry cites the report
that established the link. The tokens do not reproduce the original artifacts.
