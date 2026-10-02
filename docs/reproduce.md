# Reproduce

Every published number comes from `scripts/run_benchmarks.py`. The full run is heavy (MalwareBazaar
CSV, TLSH search over ~640k digests), so the canonical run is the
[`bench` workflow](https://github.com/rakshit-737/dragnet/actions/workflows/bench.yml) on a GitHub
`ubuntu-24.04` runner (weekly, or on dispatch). It uploads `results/` and the figures as an artifact
and checks the deterministic sections against the committed `results/benchmark.json`.

## Locally

| step | command | time / size | expected output |
|---|---|---|---|
| 1. data | `python scripts/download_data.py` | ~2-5 min, ~600 MB in `$DRAGNET_DATA` (default `data/raw`) | `[ok]` / `[have]` per source; pinned sources are SHA-256 checked and listed in `data/MANIFEST.json` |
| 2. graph | `python -m dragnet build-kg` | ~20 s | `kg-attack-19.2.json` with 176 groups, 1600 signal keys |
| 3. light sections | `PYTHONHASHSEED=0 python scripts/run_benchmarks.py --only A1,A1LF,A2,A3,C,D,F,G` | ~3 min, < 1 GB RAM | merges into `results/benchmark.json` |
| 4. full run | `PYTHONHASHSEED=0 python scripts/run_benchmarks.py --fresh --out fresh` | 1213 s on the runner (2 vCPU); needs `.[bench]` (numpy) and ~4 GB RAM | a complete `fresh/RESULTS.md` |
| 5. compare | `python scripts/compare_results.py results/benchmark.json fresh/benchmark.json` | seconds | `[ok]` for deterministic sections |

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
| R-kfold | DRAGNET top-1 / selective acc. | 0.454 / 0.853 (n = 637) |
| R-temporal | DRAGNET top-1 | 0.207 (n = 193) |
| G | DRAGNET mean rank of 29 | 5.38 +/- 0.79 |
| D level 2 | false-flag rule effect | 0.228 [0.108, 0.368] |

Sections B3, E1, E2 and E3 use the daily abuse.ch exports and the live Malpedia API, so they drift
from week to week; `compare_results.py` reports them as `[info]` and does not compare them.
