# ADR 0001 - Seed the knowledge graph from public CTI, not hand-made fixtures

- Status: accepted (v0.2.0)
- Date: 2026-09-26

## Context

The MVP matched evidence against a synthetic `campaigns.json` with made-up actors (`LAZARUS_SIM`)
and reserved-range IOCs. That was enough to exercise the ACH logic but said nothing about whether
the approach works on the real, messy, overlapping actor landscape analysts deal with.

## Decision

Build the graph from public, citable sources with stable identifiers:

| Layer | Source | What it contributes |
|---|---|---|
| Actor profiles | MITRE ATT&CK Enterprise v19.2 intrusion-sets | techniques (`ttp`), malware (`family`), tools (`tool`) per group |
| Documented campaigns | ATT&CK campaign objects + `attributed-to` | ground truth for benchmarks; optional graph layer |
| Aliases, sponsor state | MISP galaxy `threat-actor` (pinned commit) | alias resolution, `country`, coarse `language` signal |
| Family synonyms | MISP galaxy `malpedia` (pinned commit) | `WannaCryptor` == `WannaCry`, used to join abuse.ch labels to ATT&CK |
| IOC layer | abuse.ch ThreatFox export | ip/domain/hash signals for actor-specific families |
| Genetics layer | abuse.ch MalwareBazaar metadata export | imphash signals for actor-specific families (never samples) |
| Reporting depth | APTnotes index | per-actor count of public reports (context + analysis F) |

Every layer is optional; the builder records its provenance in `kg.meta`. Groups are keyed by ATT&CK
name, joined across ATT&CK versions by STIX id, and to MISP by `G####` synonym first, then aliases.

The synthetic graph stays as the fast demo/test fixture for the five spec scenarios.

## Consequences

- Benchmarks become meaningful: 176 real actors, many with overlapping tooling (Mimikatz is used by
  dozens of groups), which forced ADR 0002.
- ATT&CK is itself an attribution product. Using its campaign attributions as ground truth measures
  agreement with MITRE's analysts, not "truth"; the README states this.
- abuse.ch exports are live feeds, so their checksums are recorded in `data/MANIFEST.json` rather
  than pinned; ATT&CK/MISP/APTnotes are pinned by version or commit.
