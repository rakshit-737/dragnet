# ADR 0002 - Weight signals by specificity; compare TTPs as an IDF profile

- Status: accepted (v0.2.0)
- Date: 2026-09-26

## Context

On the synthetic graph every signal belonged to one actor. On ATT&CK, a technique like T1059 or a
tool like Mimikatz links to dozens of groups. The MVP's per-signal noisy-OR then lets the best
documented actors (APT28, Lazarus, APT29 with 100+ techniques) win almost every case simply by
having more edges, and every case produced dozens of "contradicting" signals.

## Decision

1. **Specificity.** A point signal's effective weight is `kind_weight x 1/|actors it links to|`.
   An exclusive family counts fully; Mimikatz used by 60 groups counts 1/60.
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

Ablation A1 (see `results/RESULTS.md`): removing specificity drops top-1 from 0.68 to 0.60;
replacing the profile term with per-TTP noisy-OR drops it to 0.60. The IDF-cosine is also exposed
as a standalone `ttp-cosine` baseline so its contribution can be seen in isolation.
