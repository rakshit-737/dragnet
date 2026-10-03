# Getting started

## Install

```bash
git clone https://github.com/rakshit-737/dragnet-actor-attribution && cd dragnet
python -m pip install -e ".[dev]"          # runtime is stdlib-only
python -m pytest -q                        # real-data tests skip without downloads
```

Optional extras: `api` (FastAPI server), `sign` (Ed25519 custody signatures, needs `cryptography`),
`bench` (matplotlib figures), `docs` (this site).

Or with Docker:

```bash
docker run --rm ghcr.io/rakshit-737/dragnet-actor-attribution demo
docker run --rm -v "$PWD:/w" ghcr.io/rakshit-737/dragnet-actor-attribution assess /w/case.json --format json
docker compose up api                      # FastAPI on http://127.0.0.1:8000/docs
```

## Synthetic demo (no downloads)

```bash
python -m dragnet demo
python -m dragnet assess dragnet/data/cases/olympic_destroyer_like.json
python -m dragnet assess dragnet/data/cases/wannacry_like.json --weight imphash=0.2   # auditability
```

## Real data (~640 MB of public metadata)

```bash
python scripts/download_data.py            # pinned versions + SHA-256 manifest
python -m dragnet build-kg                 # -> $DRAGNET_DATA/kg-attack-19.2.json
python -m dragnet case-study olympic_destroyer_2018 --format md
python scripts/run_benchmarks.py           # full run ~25-40 min on a GitHub runner; see reproduce.md
```

`make` targets (`make data`, `make bench`, `make demo`, `make test`) mirror these commands.

## From REVENANT / VITRINE output to an assessment

Runs from a fresh clone; the two exports are bundled test fixtures.

```bash
python -m dragnet import incident-7 --revenant fixtures/adapters/revenant_export.json     --vitrine fixtures/adapters/vitrine_triage.json -o case.json
python -m dragnet assess case.json --format md                    # add --kg "$DRAGNET_DATA/kg-attack-19.2.json" for real data
python -m dragnet assess case.json --format stix -o bundle.json   # STIX 2.1 bundle
```

## Signed, verifiable reports

Needs the `sign` extra (`pip install -e ".[sign]"`).

```bash
python -m dragnet keygen analyst                                  # analyst.key (keep it private) / analyst.pub
python -m dragnet assess case.json --sign-key analyst.key -o report.json
python -m dragnet verify report.json --pub analyst.pub            # exit 1 if the verdict, scores, weights or custody changed
```

The Ed25519 signature covers the whole JSON report body (verdict, confidence, hypotheses, weights,
ACH matrix, flags) and the head of the custody hash chain. `verify` without `--pub` checks integrity
against the key embedded in the report and exits 3 unless `--allow-unpinned` is given; reports signed
by DRAGNET 1.1.0 or earlier (custody chain only) are reported as LEGACY (exit 3).
