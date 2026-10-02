# Contributing to DRAGNET

Thanks for helping. DRAGNET is a defensive, analyst-support tool; contributions must keep it that way.

## Ground rules

- **No malware.** Never add sample binaries, packed payloads, exploit code or download logic for them.
  Malware evidence is always a JSON *feature record* (hashes, imphash, family label, TTPs).
- **No datasets in git.** Anything over ~1 MB goes through `scripts/download_data.py` (with a pinned
  version/commit or a manifest checksum). Small derived artefacts (result tables, PNG figures under
  ~500 KB, tiny test fixtures) are fine.
- **No real victim data** in fixtures or examples.
- **Every attribution rule must be explainable.** New scoring terms or false-flag rules need a sentence
  in the report output and an ADR in `docs/adr/` if they change behaviour.
- **Curated cases need sources.** Each file in `dragnet/data/real_cases/` names its ground-truth basis and
  public references; every `kg_additions` entry carries a `source`.

## Development

```bash
python -m pip install -e ".[dev,api,bench]"
python -m ruff check .
python -m pytest -q                         # real-data tests skip without downloads
python scripts/download_data.py             # optional, ~300 MB
python scripts/run_benchmarks.py            # regenerates results/ and docs/figures/
```

`make` targets mirror these commands (`make test`, `make lint`, `make data`, `make bench`, `make demo`).

## Pull requests

- Conventional-commit subjects (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`, `refactor:`, `ci:`).
- Small, focused commits; tests for new behaviour; CI must be green without the datasets.
- If a change moves benchmark numbers, re-run `scripts/run_benchmarks.py` and commit the updated
  `results/` so README claims stay reproducible.
