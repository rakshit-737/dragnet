# DRAGNET

**Evidence-to-actor attribution that says "I don't know" when it should.**

DRAGNET turns incident evidence (forensic artifacts and malware feature records) into a
confidence-graded, ACH-audited attribution assessment. It fuses infrastructure, malware genetics,
tooling and ATT&CK techniques into an Analysis of Competing Hypotheses with mandatory `FALSE_FLAG`
and `UNKNOWN` hypotheses, a conservative confidence ladder and a hash-chained (optionally
Ed25519-signed) custody log. It is evaluated on real public threat intelligence: MITRE ATT&CK,
MISP galaxy, abuse.ch metadata and APTnotes.

!!! note "Headline (ATT&CK campaigns, n = 25)"
    DRAGNET ranks the attributed group first in **68%** of campaigns (95% CI 48-84%) and **never
    commits at MEDIUM+ to a wrong actor**. The MISP-style indicator-correlation baseline gets 56% and
    commits to a wrong actor in 24% of cases. With a planted Rich header and decoy-language strings,
    DRAGNET flags every case and confidently names the decoy in **0%** (baseline 52%).

| Where to go | |
|---|---|
| [Getting started](getting-started.md) | install, demo, first assessment |
| [Architecture](architecture.md) | pipeline, scoring, false-flag rules, confidence ladder |
| [Benchmarks](benchmarks.md) | every number, with confidence intervals |
| [Demo reports](demo/index.md) | static rendered reports + STIX bundles |
| [CLI](reference/cli.md) / [REST](reference/rest.md) / [Python API](reference/python.md) | reference |
| [Limitations](limitations.md) | what DRAGNET cannot do |

!!! warning "Attribution is an analytic judgment, not proof"
    DRAGNET is defensive decision support. Its output must not be the sole basis for public
    naming, sanctions or any "hack-back". It never downloads, stores or executes malware.
