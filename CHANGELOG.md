# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- README and the Overview, Evaluation, Limitations and Reproduce pages are rendered from `templates/` by
  `scripts/render_docs.py`, which fills every value from `results/benchmark.json` and the bench run's
  `results/time.txt` (runtime 1045 s, peak RSS 968 MiB, run 37092539472); CI fails on a stale render or
  any leftover `@@TOKEN@@`. The runtime is stated as single-threaded wall clock (the run used 100% of
  one CPU) instead of an unmeasured vCPU count.

## [1.1.1] - 2026-10-03

### Fixed
- Monte Carlo sign-flip p-values are reported as `(k+1)/(B+1)` instead of 0; paired difference tests on
  the per-report set are clustered by threat group, matching the marginal CIs.
- The temporal split dates ATT&CK citations from their reference descriptions (fallback: key year), so
  post-2021 reports no longer leak into the pre-2022 profiles.
- Ed25519 signatures cover the canonical report body and the custody-chain head, so editing the verdict,
  confidence, flags, scores or weights fails `verify`; chain-only signatures are flagged LEGACY.
- The bench reproducibility gate can now fail and compares every deterministic value (runs under
  `bash -eo pipefail`).
- CLI help shows each default once; install hints point at an installable source.

### Added
- Bench results record their source run (id, URL, commit) and support `--render-only`; group-clustered
  paired tests, a temporal sensitivity run and intervals for every reported statistic; the APTMalware
  (section K) overlap analysis.
- Markdown reports print every weight and list false-flag actors as plain text.
- Figures use one colour per method with 95% CI whiskers and 10-seed false-flag means.
- `httpx2` in the `api` extra; a zero-warning test suite; declared data subpackages.

### Changed
- The release workflow also tags the GHCR image with the bare semver.
- The sdist ships `scripts/`; the docs workflow parses every mermaid diagram.
- Documentation: ADRs 0002-0004, datasets, fresh-clone commands and the demo screenshot refreshed to
  match the current protocol and results.

## [1.1.0] - 2026-10-02

### Added
- Per-report ATT&CK case set (637 cases, 161 groups) with leave-report-out k-fold and temporal splits;
  A1-LF leave-report-out campaigns; cross-release/domain union (B1), rolling origin (B2) and
  Malpedia-labelled abuse.ch cases (B3).
- TLSH fuzzy genetics (stdlib digest distance, banded index) and the E3 time-split benchmark.
- Comparison with Guru, Moss & Kochenderfer (2025) under an adapted protocol (section G).
- Isotonic calibration evaluated on a temporal split; selective-risk curves; signal-family ablations.
- `bench` workflow (weekly / dispatch) that checks deterministic sections against committed results.
- Docs: How it works, Evaluation and Reproduce pages; demo screenshot; CITATION.cff, CODEOWNERS,
  Dependabot, issue and PR templates; API docstrings rendered in the reference.
- STIX 2.1 export and REVENANT / VITRINE adapters listed in the module table.

### Security
- Input-size limits, Host allow-list and escaped Markdown reports in the API; safer keygen/verify.
- Every ATT&CK/TLSH source pinned by SHA-256; downloads fail closed.
- CI: Python 3.11 in the matrix, SHA-pinned actions, wheel/sdist/Docker/Neo4j checks, least-privilege release.

### Changed
- Baselines abstain on tied top scores; DRAGNET's LOW verdicts are reported as wrong-actor-named.
- Exact Clopper-Pearson intervals and sign-flip tests with Holm correction replace percentile
  bootstrap p-values. The previously reported significant A1 advantage over ioc-correlation and
  code-only (P = 0.01) does not hold (exact p = 0.06 leaky, 0.25 leakage-controlled).
- "Calibrated confidence" wording replaced by "abstention-aware confidence grades".
- HIGH grade requires independent anchors.
- The Bayes baseline is renamed `ttp-binary-bayes`; it is not the Guru et al. scorer.
- Demo knowledge graph and cases ship as package data; CLI gains `--version` and clearer errors.

### Fixed
- A1 leakage: the headline moved from 0.68 (campaign's own reports in the profiles) to leakage-controlled numbers.
- A2 was described as a temporal hold-out although v10.1 has no campaigns; relabelled.
- E1 no longer draws an IOC-longevity conclusion the export cannot support.
- Truncated ATT&CK downloads are rejected: every pinned source has a SHA-256 and existing files are revalidated.

## [1.0.0] - 2026-09-26

### Added
- STIX 2.1 export of assessments (`assess --format stix`, `POST /assess?format=stix`): campaign,
  intrusion-set, `attributed-to` relationship with graded confidence, ACH note, ATT&CK attack-patterns.
- Ed25519-signed custody chain (optional `[sign]` extra): `dragnet keygen`, `assess --sign-key`,
  `dragnet verify` (exit 1 on any tampering, truncation or wrong signer).
- REVENANT / VITRINE adapters: `dragnet import` turns their JSON exports into a case file.
- Benchmark uncertainty: 95% bootstrap CIs (A1, A2), paired bootstrap of top-1 differences vs every
  baseline and ablation, false-flag stress test repeated over 10 decoy seeds.
- MkDocs Material documentation site on GitHub Pages with static demo reports and STIX bundles.
- Dockerfile (slim, non-root), docker-compose for the API, tag-triggered release workflow
  (GHCR image, wheel and sdist).

### Changed
- Fixtures path resolves from `$DRAGNET_FIXTURES`, the source checkout, or `./fixtures` (installed wheel).
- README: CIs and significance reported; ablation gains stated as not significant at n = 25; single-seed
  L2 false-flag figure (0.24) now shown next to its 10-seed mean (0.17 [0.12, 0.24]).

### Fixed
- E2 imphash benchmark: the collision filter was built from all MalwareBazaar samples, including the
  test period, leaking future knowledge of shared imphashes. It now uses training-period samples only;
  collision-filtered accuracy is 91.7% at 7.7% coverage (was reported as 99.7% at 4.5%).
- `scripts/download_data.py` no longer overwrites the committed `data/MANIFEST.json` on every run
  (a partial `--only` download dropped the other entries); updating it now needs `--record` and merges.

## [0.2.0] - 2026-09-26

### Added
- Real public data: `scripts/download_data.py` fetches MITRE ATT&CK v19.2 and v10.1, MISP galaxy
  (threat-actor, malpedia), APTnotes and abuse.ch ThreatFox / MalwareBazaar **metadata** exports,
  with pinned versions/commits and a SHA-256 manifest (`data/MANIFEST.json`).
- Source loaders (`dragnet/sources/`) and a knowledge-graph builder (`dragnet/kg_build.py`) with
  alias resolution, suspected sponsor state, family synonyms, IOC and imphash enrichment layers.
- Specificity-weighted signals and IDF-cosine TTP profile similarity (ADR 0002).
- False-flag rules R3 (cross-state hard evidence) and R4 (tooling vs tradecraft divergence), same-state
  overlap notes, exclusive-family anchors (ADR 0003).
- Seven curated real cases with sources: WannaCry, NotPetya, Olympic Destroyer, Turla/OilRig,
  Bangladesh Bank, Sony Pictures and a commodity-tooling control, in time-of-incident and
  retrospective modes.
- Benchmark harness (`dragnet/bench.py`, `scripts/run_benchmarks.py`): ATT&CK campaigns (A1),
  temporal hold-out (A2), novel-family attribution (A3), false-flag stress test (D), abuse.ch IOC
  shelf-life and imphash genetics (E), reporting depth (F); baselines, ablations, Brier/ECE.
- CLI commands `build-kg`, `case-study`, `export-cypher`, `serve`; optional FastAPI service;
  dependency-free Neo4j Cypher export.
- ADRs, dataset documentation, contributing guide, MIT licence, ruff in CI, Python 3.14 in the matrix.

### Changed
- Reports show the top-N hypotheses, TTP similarity, normalised probability and analyst notes.
- Tradecraft-only evidence can now reach LOW (never MEDIUM/HIGH) instead of always INSUFFICIENT.

## [0.1.0] - 2026-06

### Added
- Synthetic-data MVP: typed signals, noisy-OR ACH with mandatory FALSE_FLAG/UNKNOWN hypotheses,
  rule-based false-flag reasoner, conservative confidence ladder, hash-chained custody log,
  Markdown/JSON reports, five spec scenarios as fixtures.
