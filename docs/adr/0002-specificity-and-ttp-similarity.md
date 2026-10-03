# ADR 0002 - Weight signals by specificity; compare TTPs as an IDF profile

- Status: accepted (v0.2.0); consequences revised 2026-10-03 with the leakage-controlled per-report results
- Date: 2026-09-26

## Context

On the synthetic graph every signal belonged to one actor. On ATT&CK, a technique like T1059 or a
tool like Mimikatz links to dozens of groups. The MVP's per-signal noisy-OR then lets the best
documented actors (APT28 and Lazarus, each with 93 technique IDs in v19.2) win almost every case simply by
having more edges, and every case produced dozens of "contradicting" signals.

## Decision

1. **Specificity.** A point signal's effective weight is `kind_weight x 1/|actors it links to|`.
   An exclusive family counts fully; Mimikatz, linked to 51 groups in ATT&CK v19.2, counts 1/51.
2. **TTP profile similarity.** Techniques are not scored one by one. The case's technique set
   (sub-techniques expanded to their parents) is compared with every actor's profile by
   IDF-weighted cosine similarity; the result enters the noisy-OR as a single term weighted by
   `ttp_profile` (default 0.6). Cosine normalises away profile size; IDF makes rare tradecraft
   count more than ubiquitous techniques.
3. **Anchors.** A verdict above LOW requires an anchor: an infra/code/hash signal, or a malware
   family linked to at most two actors. Tradecraft alone can at most reach LOW.

## Alternatives considered

- Learned embeddings (e.g. doc2vec over technique sequences): more opaque, and the whole point of
  DRAGNET is that every number in a report is explainable. Rejected for the scoring path.
- Jaccard similarity: implemented as the literature baseline (`ttp-jaccard`); it is dominated by
  profile-size effects.

## Consequences

Measured on the leakage-controlled per-report cases (section R of `results/RESULTS.md`; paired
differences with group-cluster bootstrap CIs and group-level sign-flip tests):

- **Specificity is supported.** Removing it (`dragnet-no-spec`) lowers k-fold top-1 by 0.025
  [0.003, 0.048] (one-sided p = 0.014, Holm 0.041) and more than doubles the share of cases where a
  wrong actor is named (0.148 vs 0.063). On the temporal split the difference is not significant.
- **The IDF-cosine profile term is not supported on accuracy.** Replacing it with per-technique
  noisy-OR (`dragnet-no-ttpsim`) scores *higher* k-fold top-1 (0.487 vs 0.454; difference -0.034
  [-0.067, 0.004], two-sided p = 0.088 group-clustered) at lower coverage (0.336 vs 0.429). On the
  temporal split (citations dated from their reference descriptions) the full engine is ahead
  (0.137 vs 0.126; +0.011 [-0.027, 0.055], two-sided p = 0.62), and no-ttpsim names a wrong actor
  less often (0.041 vs 0.100). Neither direction is significant, so the default keeps the term for
  its coverage, and the README headline says that the ablation scores higher on the k-fold set.
- The earlier justification - A1 top-1 dropping from 0.68 to 0.60 without either component - came
  from the leaky campaign set (n = 25, one or two discordant cases, p = 0.25) and is superseded.

The IDF-cosine is also exposed as a standalone `ttp-cosine` baseline (identical ranking to
DRAGNET restricted to techniques), so its contribution can be seen in isolation.
