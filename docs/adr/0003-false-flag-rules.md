# ADR 0003 - Keep the false-flag reasoner rule-based

- Status: accepted (v0.2.0)
- Date: 2026-09-26

## Context

Olympic Destroyer (2018) carried a Rich header copied from a Lazarus sample and code fragments that
early reporting linked to Chinese groups; it was later attributed to the GRU (Sandworm). Turla ran
operations through Iranian (OilRig) tooling and infrastructure. A learned model trained on "normal"
attribution data would reward exactly the signals an adversary plants.

## Decision

Every hypothesis set contains `FALSE_FLAG` and `UNKNOWN`. Indicators are produced by four explicit
rules, each rendered as a sentence an analyst can verify:

| Rule | Fires when | Rationale |
|---|---|---|
| R1 | an actor is supported only by *discriminating* forgeable artifacts (Rich header, language, mutex linking to <= 5 actors) | planted artifacts must never carry an attribution on their own |
| R2 | forgeable artifacts and hard evidence point to disjoint actor sets | the Olympic Destroyer pattern |
| R3 | specific hard evidence points to several actors **of different sponsor states** | tool theft / shared supplier; same-state overlaps (e.g. Lazarus vs APT38) become an analyst *note*, not a flag |
| R4 | the anchored tooling/infra actor differs from a clearly better tradecraft match (IDF-cosine >= 0.3 and >= 2x) of a different state | infrastructure hijack / tool reuse (Turla-OilRig pattern) |

Any indicator caps the verdict at LOW; if `FALSE_FLAG` outscores every actor, DRAGNET withholds
attribution entirely.

## Consequences

- Measured false-alarm rate: indicators fire on 16% of clean ATT&CK campaigns (A1). Most are R4 on
  campaigns whose tradecraft is generic; the cost is a LOW instead of MEDIUM grade, never a wrong name.
- Under planted decoys (analysis D) DRAGNET never confidently names the decoy when only forgeable
  artifacts are planted, and does so in 24% of cases when an exclusive decoy family is also
  planted (MISP-style correlation: 76%). The residual cases are campaigns whose genuine evidence
  has no anchor at all - no rule can tell a stolen tool from a real one without independent evidence.
