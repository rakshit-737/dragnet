# Reproduce

Every published number comes from `scripts/run_benchmarks.py`. The full run is heavy (MalwareBazaar
CSV, TLSH search over ~640k digests), so the canonical run is the
[`bench` workflow](https://github.com/rakshit-737/dragnet-actor-attribution/actions/workflows/bench.yml) on a GitHub
`ubuntu-24.04` runner (weekly, or on dispatch). The committed results come from bench run
[@@RUN_ID@@](@@RUN_URL@@) on commit `@@RUN_SHA7@@`; `results/RESULTS.md` and `results/benchmark.json`
(`provenance`) name that run, and the run's artifact holds the same files plus `compare.txt`,
`time.txt` and the dataset manifest.

Each bench run:

1. downloads the datasets (pinned sources are SHA-256 checked),
2. runs the real-data tests and the README real-data quickstart verbatim (build-kg, case-study,
   assess --kg, export-cypher, serve + `POST /assess` on 127.0.0.1),
3. runs every benchmark section with `PYTHONHASHSEED=0`,
4. runs `scripts/compare_results.py` against the committed `results/benchmark.json`: every value of
   the deterministic sections must match (numbers to 1e-9, strings exactly, rows matched by method or
   case name), otherwise the step - and the run - fails.

## Locally

| step | command | time / size | expected output |
|---|---|---|---|
| 1. data | `python scripts/download_data.py` | ~2-5 min, ~640 MB in `$DRAGNET_DATA` (default `data/raw`) | `[get]` / `[have]` per source; pinned sources are SHA-256 checked and listed in `data/MANIFEST.json` |
| 2. graph | `python -m dragnet build-kg` | ~20 s | `kg-attack-19.2.json` with 176 groups, 1600 signal keys |
| 3. light sections | `PYTHONHASHSEED=0 python scripts/run_benchmarks.py --only A1,A1LF,A2,A3,C,D,F,G` | a few minutes, < 1 GB RAM | merges into `results/benchmark.json` |
| 4. full run | `PYTHONHASHSEED=0 python scripts/run_benchmarks.py --fresh --out fresh` | @@RUNTIME@@ s wall clock on the runner (single-threaded), peak RSS @@RSS@@ (`time.txt` of run @@RUN_ID@@); needs `.[bench]` (numpy, matplotlib) | a complete `fresh/RESULTS.md` |
| 5. compare | `python scripts/compare_results.py results/benchmark.json fresh/benchmark.json` | seconds | `[ok]` for every deterministic section, exit 0 |
| 6. re-render | `python scripts/run_benchmarks.py --render-only` | seconds | `results/RESULTS.md` and `docs/figures/` from `results/benchmark.json` |

The R section alone takes about 12 minutes on a laptop (it runs 11 methods over 637 cases in 5 folds
plus two temporal graphs, and its paired sign-flip tests use B = 200,000 Monte Carlo flips).

```bash
export DRAGNET_DATA="$PWD/data/raw"          # PowerShell: $env:DRAGNET_DATA = "$PWD\data\raw"
python -m pip install -e ".[dev,bench]"
python scripts/download_data.py
python -m dragnet build-kg
PYTHONHASHSEED=0 python scripts/run_benchmarks.py --only A1LF,A1,G
```

## Expected key numbers

Deterministic sections (ATT&CK, MISP and APTnotes are pinned) must match exactly with
`PYTHONHASHSEED=0`:

| section | quantity | value |
|---|---|---|
| A1-LF | DRAGNET top-1 | 0.400 [0.200, 0.600] |
| A1-LF | DRAGNET wrong at MEDIUM+ | 0/25 |
| A1 (leaky) | DRAGNET top-1 | 0.680 [0.480, 0.840] |
| R-kfold | DRAGNET top-1 / selective acc. | 0.454 [0.401, 0.507] / 0.853 (n = 637) |
| R-kfold | fusion gain over software-only | +0.095 [0.064, 0.130], p = 5.0e-6 (MC, B = 200,000) |
| R-temporal | DRAGNET top-1 | 0.137 [0.078, 0.214] (n = 219) |
| G | DRAGNET mean rank of 29 | 5.38 +/- 0.79 |
| D level 2 | false-flag rule effect | 0.228 [0.108, 0.368] |

Sections B3, E1, E2, E3 and K use the daily abuse.ch exports and the live Malpedia API, so they drift
from week to week; `compare_results.py` reports them as `[info]` and does not compare them.
