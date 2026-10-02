# DRAGNET

**Evidence-to-actor attribution that says "I don't know" when it should.**

DRAGNET turns incident evidence (forensic artifacts and malware feature records) into a
confidence-graded, ACH-audited attribution assessment. It fuses infrastructure, malware genetics,
tooling and ATT&CK techniques into an Analysis of Competing Hypotheses with mandatory `FALSE_FLAG`
and `UNKNOWN` hypotheses, a conservative confidence ladder and a hash-chained (optionally
Ed25519-signed) custody log. It is evaluated on real public threat intelligence: MITRE ATT&CK,
MISP galaxy, abuse.ch metadata and APTnotes.

**Contribution.** DRAGNET attributes from artifact-level evidence - host IOCs, malware genetics from
published imphash/TLSH metadata, infrastructure and ATT&CK techniques - fused with specificity
weighting and forgeability-aware false-flag rules into an ACH that abstains rather than misattributes,
evaluated leakage-controlled and time-split on public data.

[Try it in 60 seconds](getting-started.md){ .md-button .md-button--primary }
[Evaluation](benchmarks.md){ .md-button }
[How it works](how-it-works.md){ .md-button }

![DRAGNET report for the Olympic Destroyer-like demo case](figures/demo.png)

!!! note "Headline (leakage-controlled per-report ATT&CK cases, n = 637, 161 groups)"
    DRAGNET ranks the true group first in **45%** [40, 51] vs 30-31% for IOC-correlation and
    code-only matchers and 13-22% for TTP-similarity baselines; MEDIUM verdicts are right 79/83
    times. On the 25 ATT&CK campaigns with their own reports removed from the profiles, top-1 is
    0.40 and the edge over IOC correlation is not significant. With a stolen decoy family planted,
    the false-flag rules cut confident decoy attributions from 0.40 to 0.17.

![A1 methods](figures/a1_methods.png)

| Where to go | |
|---|---|
| [Getting started](getting-started.md) | install, demo, first assessment |
| [Architecture](architecture.md) | pipeline, scoring, false-flag rules, confidence ladder |
| [How it works](how-it-works.md) | one case traced through the pipeline |
| [Evaluation](benchmarks.md) | protocol, every number, confidence intervals, published comparison |
| [Reproduce](reproduce.md) | commands, runtimes, expected values |
| [Datasets](datasets.md) | sources, pins, licences |
| [ADRs](adr/0004-evaluation-protocol.md) | design decisions |
| [Threat model](threat-model.md) / [Changelog](changelog.md) | security model, history |
| [Demo reports](demo/index.md) | static rendered reports + STIX bundles |
| [CLI](reference/cli.md) / [REST](reference/rest.md) / [Python API](reference/python.md) | reference |
| [Limitations](limitations.md) | what DRAGNET cannot do |

!!! warning "Attribution is an analytic judgment, not proof"
    DRAGNET is defensive decision support. Its output must not be the sole basis for public
    naming, sanctions or any "hack-back". It never downloads, stores or executes malware.
