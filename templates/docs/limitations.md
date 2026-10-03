# Limitations and roadmap

## Limitations

- **Small curated n.** 25 attributed campaigns (26 across all releases and domains) and 7 curated cases.
  Per-report cases (n = 637) are the larger set; leave-report-out reduces but does not remove overlap.
- **Ground truth is itself attribution.** ATT&CK, Malpedia and government statements can be wrong.
- **Leakage.** Plain A1 (0.68) is a leaky upper bound; A1-LF (0.40) and R are the controlled numbers.
  The temporal split dated citations only by their key until this release, which kept 52 post-2021
  reports in the "pre-2022" profiles; dated from their reference descriptions, DRAGNET's temporal
  top-1 is 0.137 (it was reported as 0.207).
- **The default engine is not the best ablation on the 5-fold per-report set**: without the TTP-profile
  term top-1 is 0.487 vs 0.454 (not significant with group clustering, p = 0.088); the temporal split
  does not decide it ([ADR 0002](adr/0002-specificity-and-ttp-similarity.md)).
- **Artifact-level fusion is not shown to beat plain lookups** on imphash and TLSH metadata (E2, E3).
- **Genetics is dominated by commodity families** (AgentTesla, WannaCry).
- **Tradecraft-only LOW verdicts are unreliable** (A3: 0/10 correct; R-temporal LOW 18/40).
- **Raw scores are not calibrated**; an isotonic map fitted on pre-2022 cases brings temporal ECE from
  0.157 to 0.073 [0.055, 0.145].
- **Zero confident errors is not a zero error rate**: 0/25 has an exact 95% upper bound of 0.137.
- **Adapters are file-based.** **Signing** proves that the report body and custody chain are unchanged
  and, with a pinned key, who signed; key management and trusted timestamps are out of scope, and STIX
  bundles are not signed.

## Not done, and why

| Item | Why it stays open |
|---|---|
| Victimology signals | MISP sector/country metadata exists but is not yet wired into the graph |
| OCCAM STIX import | file-format adapter not written yet |
| Live sample handling | by design: DRAGNET never touches binaries |
| Matching Kida & Olukoya (2023) | needs the APTMalware binaries; section K counts how many of its @@K_DISTINCT@@ hashes MalwareBazaar metadata knows (@@K_FOUND@@) |

## Roadmap

- [x] Real knowledge graph from ATT&CK + MISP + abuse.ch with provenance
- [x] Leave-report-out and per-report evaluation, rolling-origin release split
- [x] TLSH fuzzy genetics with a banded index and a time-split benchmark
- [x] Isotonic calibration on a temporal split; Guru et al. (2025) comparison
- [x] Neo4j export, FastAPI service, STIX 2.1 export, Ed25519-signed reports, adapters
- [ ] Victimology signals; OCCAM import
