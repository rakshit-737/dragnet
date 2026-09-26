# ADR 0004 - Evaluation protocol: leakage controls, open world, abstention-aware metrics

- Status: accepted (v0.2.0)
- Date: 2026-09-26

## Context

Attribution benchmarks leak easily: if the knowledge graph already contains the incident's own
malware family, "attribution" is a dictionary lookup. And accuracy alone rewards guessing, which
is the behaviour the spec wants to prevent.

## Decision

Benchmarks (all in `scripts/run_benchmarks.py`, logic in `dragnet/bench.py`):

| Id | Cases | Graph | Leakage control |
|---|---|---|---|
| A1 | 25 attributed ATT&CK v19.2 campaigns | v19.2 group profiles (campaign layer excluded) | campaign objects not in graph; residual overlap via shared software is acknowledged |
| A2 | same campaigns, created after ATT&CK v10.1 | v10.1 profiles | temporal: profiles frozen before the campaigns were documented; groups absent in v10.1 make the case open-world (correct answer: abstain) |
| A3 | 411 malware families used by exactly one group | v19.2 profiles | family name withheld; evidence = its documented techniques only |
| C | 7 curated real cases | v19.2 + sourced prior knowledge | "time-of-incident" mode hides families first seen in the incident |
| D | A1 cases + planted decoy artifacts | v19.2 + simulated reference Rich headers | decoy drawn from a different sponsor state, seeded |
| E1/E2 | abuse.ch IOCs / imphashes of actor-specific families | temporal split | train strictly before test |

Metrics: top-k with ties scored in expectation (no alphabetical luck), MRR, coverage (share of
in-graph cases where a method names an actor), selective accuracy, **confident-error rate** (share
of all cases where a method commits - MEDIUM+ for DRAGNET, always for baselines - to a wrong actor),
Brier and ECE on the binary forecast "the top-ranked actor is correct", plus accuracy per stated
DRAGNET grade.

## Consequences

Numbers are small-n (25 campaigns) and reported with that caveat. Ground truth is the public
attribution of record (ATT&CK, government indictments), which can itself be wrong.
