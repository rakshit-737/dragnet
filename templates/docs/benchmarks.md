# Evaluation

All numbers come from `python scripts/run_benchmarks.py`, run by the `bench` GitHub Actions workflow
on the dataset snapshot in `data/MANIFEST.json`. **Source of every number on this page: bench run
[@@RUN_ID@@](@@RUN_URL@@) on commit `@@RUN_SHA7@@`** (also printed at the top of the generated results
below). Commands and expected values: [Reproduce](reproduce.md). Protocol details:
[ADR 0004](adr/0004-evaluation-protocol.md).

## Protocol in brief

- **Leave-report-out.** Before a case is attributed, every group edge whose citations are a subset
  of the case's own citations is removed (A1-LF, R, G). Plain A1 is kept only as a leaky upper bound.
- **Per-report cases (R).** One case per (group, cited report) with at least 3 techniques: 637 cases
  over 161 groups; 5-fold by report, and a temporal split: every citation dated 2022 or later is
  removed from the profiles (date from the citation's reference description "(YYYY, Month DD)", else
  from a year in its key) and the 219 cases from 2022+ reports are attributed. A sensitivity run also
  removes the 83 citations with no recoverable date.
- **Commitment rule.** Baselines commit only on a unique top score (ties abstain); DRAGNET commits at
  MEDIUM+, and its LOW verdicts are counted separately as "wrong actor named (any grade)".
- **Uncertainty.** Exact Clopper-Pearson intervals for proportions; bootstrap CIs for top-1 that
  resample the non-independent unit (threat groups for R, cases for the campaign sets, families for
  genetics, actors for G). Paired differences: sign-flip test, exact when at most 20 discordant units,
  otherwise Monte Carlo with B = 200,000 sign flips and p = (k+1)/(B+1) (never reported as 0); on R the
  test flips whole groups, matching the clustered CIs; Holm correction across methods.
- **Genetics (E2/E3, B3).** Time split at 2024-01-01; collision filters and the TLSH radius use
  pre-cutoff or validation data only; results per family and with WannaCry excluded.
- **Published comparison (G).** Guru, Moss & Kochenderfer (2025) adapted to ATT&CK human-curated
  per-report technique lists; an adaptation, not a reproduction (the paper picks the best of 10 weight
  matrices on validation; we report every split).

## What the results say

1. On leakage-controlled per-report cases DRAGNET beats every single-signal and TTP baseline on top-1:
   5-fold 0.454 [0.401, 0.507] vs at most 0.310 (group-clustered Holm p = 5.0e-5, Monte Carlo with
   B = 200,000); temporal 0.137 [0.078, 0.214] vs at most 0.078 (Holm p <= 0.010).
2. The gain comes from fusing techniques with software (+0.095 [0.064, 0.130] over software-only,
   p = 5.0e-6, B = 200,000) and from specificity weighting (+0.025 [0.003, 0.048], Holm p = 0.041).
3. The ablation without the TTP-profile term scores higher on 5-fold top-1 (0.487 vs 0.454, not
   significant with group clustering: two-sided p = 0.088), and the temporal split does not decide it.
4. On the 25 campaigns, with leakage removed, the edge over IOC correlation (+0.046 [-0.027, 0.147]) is
   not significant (exact p = 0.25).
5. Tradecraft-only LOW verdicts are unreliable (A3 0/10; R-temporal LOW 18/40); MEDIUM verdicts are
   reliable (R 5-fold: 79/83, 0.95 [0.88, 0.99]).
6. The false-flag rules matter only when a hard decoy anchor is planted (level 2: -0.23 [-0.37, -0.11]).
7. Imphash and TLSH genetics are precise but rare anchors, mostly re-identify commodity families, and
   DRAGNET does not beat a plain lookup on them.

![Per-report ablations](figures/signal_contribution.png)

*Figure 1. Per-report cases, 5-fold: top-1, coverage and selective accuracy of DRAGNET, its ablations and
two baselines, with 95% CIs (top-1 group-cluster bootstrap, rates Clopper-Pearson).*

![A1-LF methods](figures/a1_methods.png)

*Figure 2. The 25 campaigns with leave-report-out profiles: top-1, coverage and wrong commitments per
method, with 95% CIs.*

![False-flag stress test](figures/false_flag.png)

*Figure 3. Confident decoy attributions at decoy levels 1 and 2, mean over 10 decoy seeds (whiskers:
seed range), with the rules' level-2 effect and its case-clustered CI.*

![Reliability](figures/reliability.png)

*Figure 4. Reliability of DRAGNET's top-hypothesis score on the temporal test set, raw and after the
isotonic map fitted on pre-2022 cases (ECE with group-cluster bootstrap CIs).*

## Full generated results

--8<-- "results/RESULTS.md:3:"
