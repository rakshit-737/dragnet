# DRAGNET

**Evidence-to-actor attribution that says "I don't know" when it should.**

DRAGNET turns incident evidence (forensic artifacts and malware feature records) into a
confidence-graded, ACH-audited attribution assessment. It fuses infrastructure, malware genetics,
tooling and ATT&CK techniques into an Analysis of Competing Hypotheses with mandatory `FALSE_FLAG`
and `UNKNOWN` hypotheses, a conservative confidence ladder and a hash-chained (optionally
Ed25519-signed) custody log. It is evaluated on real public threat intelligence: MITRE ATT&CK,
MISP galaxy, abuse.ch metadata and APTnotes.

**Contribution.** DRAGNET fuses tooling and technique evidence (and, when a case has them, host IOCs,
imphash/TLSH genetics and infrastructure) with specificity weighting into an ACH that abstains rather
than misattributes: on leakage-controlled per-report ATT&CK cases, fusing techniques with software adds
+0.095 [0.064, 0.130] top-1 over the same engine on software alone and specificity weighting adds +0.025
[0.003, 0.048]; forgeability-aware false-flag rules cut confident decoy attributions by 0.23 [0.11, 0.37].
The IOC, imphash and TLSH layers are supported inputs whose gain over plain lookups is not shown.

[Try it in 60 seconds](getting-started.md){ .md-button .md-button--primary }
[Evaluation](benchmarks.md){ .md-button }
[How it works](how-it-works.md){ .md-button }

![DRAGNET report for the Olympic Destroyer-like demo case](figures/demo.png)

## Headline results

Per-report ATT&CK cases (n = 637 over 161 groups), leave-report-out profiles, 95% CIs bootstrapped over
threat groups. Source: bench run [@@RUN_ID@@](@@RUN_URL@@) on commit `@@RUN_SHA7@@`.

| method | top-1, 5-fold | top-1, temporal 2022+ (n = 219) | names an actor | right when it names one | wrong actor named |
|---|---|---|---|---|---|
| **DRAGNET** (default engine) | **0.454** [0.401, 0.507] | **0.137** [0.078, 0.214] | 0.429 | 0.853 | 0.063 |
| DRAGNET without the TTP-profile term (ablation) | 0.487 [0.423, 0.541] | 0.126 [0.069, 0.194] | 0.336 | 0.921 | 0.027 |
| malware-family count (`code-only`) | 0.310 [0.251, 0.366] | 0.062 [0.027, 0.107] | 0.323 | 0.913 | 0.028 |
| MISP-style software-overlap count (`ioc-correlation`) | 0.301 [0.245, 0.356] | 0.052 [0.024, 0.090] | 0.349 | 0.788 | 0.074 |
| TTP profile, IDF-cosine (`ttp-cosine`) | 0.218 [0.160, 0.285] | 0.078 [0.034, 0.139] | 0.983 | 0.222 | 0.765 |
| TTP profile, Jaccard (`ttp-jaccard`) | 0.126 [0.084, 0.180] | 0.050 [0.020, 0.091] | 0.936 | 0.133 | 0.812 |

!!! note "Read the headline with these caveats"
    - The lead over every baseline is significant with group-clustered sign-flip tests (5-fold Holm
      p = 5.0e-5, Monte Carlo with B = 200,000; temporal Holm p <= 0.010). MEDIUM verdicts are right 79/83
      times (0.95 [0.88, 0.99]).
    - **The no-TTP-profile ablation scores higher on 5-fold top-1** (0.487 vs 0.454; -0.034 [-0.067, 0.004],
      two-sided p = 0.088); on the temporal split the default is ahead (0.137 vs 0.126, p = 0.62). Neither is
      significant; the default is kept for coverage ([ADR 0002](adr/0002-specificity-and-ttp-similarity.md)).
    - On the 25 ATT&CK campaigns with their own reports removed, top-1 is 0.40 [0.20, 0.60] and the edge
      over IOC correlation is not significant (p = 0.25). With a stolen decoy family planted, the false-flag
      rules cut confident decoy attributions from 0.40 to 0.17 (effect 0.23 [0.11, 0.37]).

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
