# ADR 0004 - Evaluation protocol: leakage controls, open world, abstention-aware metrics

- Status: accepted (v0.2.0); revised 2026-10-03 (leave-report-out, per-report cases, clustered tests)
- Date: 2026-09-26

## Context

Attribution benchmarks leak easily: if the knowledge graph already contains the incident's own
malware family, or a group profile was written from the very report being attributed, "attribution"
is a dictionary lookup. And accuracy alone rewards guessing, which is the behaviour the spec wants to
prevent.

## Decision

Benchmarks live in `scripts/run_benchmarks.py` (logic in `dragnet/bench.py` and
`dragnet/protocols.py`); the [Evaluation page](../benchmarks.md) shows every result.

| Id | Cases | Graph | Leakage control |
|---|---|---|---|
| A1 | 25 attributed ATT&CK v19.2 campaigns | v19.2 group profiles | campaign objects not in the graph; the campaign's own reports still shape the profiles, so A1 is a **leaky upper bound** |
| A1-LF | same 25 campaigns | v19.2 profiles minus every group edge cited only by the campaign's own reports | leave-report-out |
| A2 | same campaigns | ATT&CK v10.1 profiles | **not** a temporal hold-out (v10.1 has no campaigns): stale, open-world profiles; groups absent in v10.1 should be abstained on |
| A3 | 411 malware families used by exactly one group | v19.2 profiles | family name withheld; evidence = its documented techniques only |
| R | 637 per-report cases (group x cited report, >= 3 techniques), 161 groups | 5-fold leave-report-out; and a temporal split | k-fold: a fold's reports are removed from the profiles; temporal: every citation dated 2022 or later (date from the reference description, else the citation key) is removed and the cases from 2022+ reports are attributed; sensitivity run also removes undated citations |
| G | 29 actors of Guru et al. (2025), 261 reports | per split, validation/test reports removed | 70/20/10 per-actor splits, 10 seeds |
| B1/B2 | campaign union over ATT&CK 12.1-19.2 (Enterprise, ICS, Mobile); rolling origin | per case, the newest release published before the campaign was added (B2) | leave-report-out (B1); release dates (B2) |
| B3 | Malpedia-labelled abuse.ch cases | ATT&CK v14.1 + pre-2024 abuse.ch | labels from a source the graph does not use; time split at 2024-01-01 |
| C | 7 curated real cases | v19.2 + sourced prior knowledge | "time-of-incident" hides families first seen in the incident; demonstrations, not validation |
| D | A1 cases + planted decoy artifacts, 10 seeds | v19.2 + simulated reference Rich headers | decoys from another sponsor state |
| E1/E2/E3 | abuse.ch IOCs, imphashes, TLSH digests of actor-specific families | pre-2024 data only | time split at 2024-01-01; collision filters and the TLSH radius chosen on pre-cutoff / validation data |
| F | A1 cases by APTnotes reporting depth | v19.2 | association only |
| K | APTMalware hash list vs MalwareBazaar metadata | - | literature check (no binaries) |

**Commitment.** A baseline commits only when one actor holds the unique top score (a tie abstains);
DRAGNET commits at MEDIUM or HIGH, and its LOW verdicts are counted as "wrong actor named (any
grade)" when wrong.

**Metrics.** Top-k with ties scored in expectation, MRR, coverage, selective accuracy,
confident-error rate, wrong actor named at any grade, Brier and ECE of the forecast "the top-ranked
actor is correct", selective risk at fixed coverage and AURC, accuracy per stated DRAGNET grade.

**Uncertainty.** Exact Clopper-Pearson intervals for proportions; bootstrap CIs for top-1 that
resample the unit that is not independent (cases for the campaign sets, threat groups for R,
families for genetics, actors for G); paired differences with a sign-flip test - exact up to 20
discordant units, otherwise Monte Carlo with B = 200,000 and p = (k+1)/(B+1) - clustered by group on
R, and Holm-adjusted across the compared methods. Every published number comes from a `bench`
workflow run whose id and commit are printed at the top of `results/RESULTS.md`.

## Consequences

Numbers on the campaign sets are small-n (25) and reported with that caveat; the per-report set is
larger but its cases are slices of the same reports the profiles come from (handled by
leave-report-out, not eliminated). Ground truth is the public attribution of record (ATT&CK,
Malpedia, government statements), which can itself be wrong.
