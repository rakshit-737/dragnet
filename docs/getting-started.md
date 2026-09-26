# Getting started

## Install

```bash
git clone https://github.com/rakshit-737/dragnet && cd dragnet
python -m pip install -e ".[dev]"          # runtime is stdlib-only
python -m pytest -q                        # real-data tests skip without downloads
```

Optional extras: `api` (FastAPI server), `sign` (Ed25519 custody signatures, needs `cryptography`),
`bench` (matplotlib figures), `docs` (this site).

Or with Docker:

```bash
docker run --rm ghcr.io/rakshit-737/dragnet demo
docker run --rm -v "$PWD:/w" ghcr.io/rakshit-737/dragnet assess /w/case.json --format json
docker compose up api                      # FastAPI on http://127.0.0.1:8000/docs
```

## Synthetic demo (no downloads)

```bash
python -m dragnet demo
python -m dragnet assess fixtures/cases/olympic_destroyer_like.json
python -m dragnet assess fixtures/cases/wannacry_like.json --weight imphash=0.2   # auditability
```

## Real data (~320 MB of public metadata)

```bash
python scripts/download_data.py            # pinned versions + SHA-256 manifest
python -m dragnet build-kg                 # -> $DRAGNET_DATA/kg-attack-19.2.json
python -m dragnet case-study olympic_destroyer_2018 --format md
python scripts/run_benchmarks.py           # ~5-8 min; writes results/ and docs/figures/
```

`make` targets (`make data`, `make bench`, `make demo`, `make test`) mirror these commands.

## From REVENANT / VITRINE output to an assessment

```bash
python -m dragnet import incident-7 --revenant revenant_export.json --vitrine triage.json -o case.json
python -m dragnet assess case.json --kg "$DRAGNET_DATA/kg-attack-19.2.json" --format md
```

## Signed, verifiable reports

```bash
python -m dragnet keygen analyst
python -m dragnet assess case.json --sign-key analyst.key -o report.json
python -m dragnet verify report.json --pub analyst.pub     # exit code 1 if anything changed
python -m dragnet assess case.json --format stix -o bundle.json
```
