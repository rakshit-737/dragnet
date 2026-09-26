# Benchmarks and results

All numbers come from `python scripts/run_benchmarks.py` on the dataset snapshot recorded in
`data/MANIFEST.json`. Protocol: [ADR 0004](adr/0004-evaluation-protocol.md). Methods:

- `dragnet` - the full engine;
- `ttp-jaccard` - nearest actor by Jaccard over techniques (common literature baseline);
- `ttp-cosine` - DRAGNET's IDF-cosine TTP term alone;
- `ioc-correlation` - MISP-style count of shared families/tools/IOCs;
- `code-only` - shared family/imphash/code count (Malpedia/Intezer-style single signal).

Because n is small (25 campaigns), the tables below include 95% percentile-bootstrap confidence
intervals over cases and a paired bootstrap of top-1 differences. The false-flag stress test is
repeated over 10 decoy seeds.

![A1 methods](figures/a1_methods.png)

![False-flag stress test](figures/false_flag.png)

![Reliability](figures/reliability.png)

## Full generated results

--8<-- "results/RESULTS.md"
