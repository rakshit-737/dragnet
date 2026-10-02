# Limitations and roadmap

## Limitations

- **Small curated n.** 25 attributed campaigns (26 across all releases and domains) and 7 curated cases.
  Per-report cases (n = 637) are the larger set; leave-report-out reduces but does not remove overlap.
- **Ground truth is itself attribution.** ATT&CK, Malpedia and government statements can be wrong.
- **Leakage.** Plain A1 (0.68) is a leaky upper bound; A1-LF (0.40) and R are the controlled numbers.
- **Genetics is dominated by commodity families** (AgentTesla, WannaCry).
- **Tradecraft-only LOW verdicts are unreliable** (A3: 0/10 correct).
- **Raw scores are not calibrated**; an isotonic map on a temporal split brings ECE to 0.051.
- **Zero confident errors is not a zero error rate**: 0/25 has an exact 95% upper bound of 0.137.
- **Monte-Carlo p-values print as 0.000.** Where the sign-flip test falls back to Monte Carlo
  (B = 200,000 sign flips, more than 20 discordant pairs), RESULTS.md prints 0.000; read these as
  p < 1/(B+1) = 5e-6. The reporting fix lands with the next bench run.
- **Headline engine is not the best ablation on the per-report set**: no-ttpsim scores 0.487 top-1
  versus 0.454 for the full engine.
- **One test warning** (Starlette TestClient / httpx deprecation) remains.
- **Adapters are file-based**; **signing** proves integrity and, with a pinned key, signer identity.

## Not done, and why

| Item | Why it stays open |
|---|---|
| Victimology signals | MISP sector/country metadata exists but is not yet wired into the graph |
| OCCAM STIX import | file-format adapter not written yet |
| Live sample handling | by design: DRAGNET never touches binaries |
| Matching Kida & Olukoya (2023) | needs the APTMalware binaries; only 12 of 3,719 hashes are in MalwareBazaar metadata |

## Roadmap

- [x] Real knowledge graph from ATT&CK + MISP + abuse.ch with provenance
- [x] Leave-report-out and per-report evaluation, rolling-origin release split
- [x] TLSH fuzzy genetics with a banded index and a time-split benchmark
- [x] Isotonic calibration on a temporal split; Guru et al. (2025) comparison
- [x] Neo4j export, FastAPI service, STIX 2.1 export, Ed25519-signed custody, adapters
- [ ] Victimology signals; OCCAM import
