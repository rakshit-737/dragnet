# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

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
