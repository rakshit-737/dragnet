# CLI reference

`python -m dragnet <command>` (or the `dragnet` console script).

| Command | Purpose |
|---|---|
| `assess CASE [--kg KG] [--weight kind=w ...] [--format md\|json\|stix] [--sign-key KEY] [-o OUT]` | assess one case file; `--sign-key` writes the JSON report with an Ed25519 signature over its body and custody chain (not with `stix`) |
| `demo [--kg KG]` | run the bundled synthetic scenarios |
| `build-kg [--attack-version 19.2] [--with-campaigns] [--data DIR] [-o OUT]` | build a knowledge graph from downloaded ATT&CK/MISP |
| `case-study [NAME] [--mode time-of-incident\|retrospective] [--format summary\|md\|json]` | curated real cases (needs data) |
| `export-cypher [--kg KG] [--case CASE] [-o OUT]` | Neo4j Cypher script |
| `serve [--kg KG] [--host 127.0.0.1] [--port 8000] [--allowed-host NAME ...]` | optional FastAPI server (needs `[api]`) |
| `keygen PREFIX [--force]` | Ed25519 key pair `PREFIX.key` (mode 0600) / `PREFIX.pub` (needs `[sign]`) |
| `verify REPORT [--pub PUB] [--allow-unpinned]` | check the custody chain and, if present, the signature over the report body; exit 0 valid, 1 tampered, 3 valid but signer not pinned or a legacy chain-only signature |
| `import CASE_ID [--revenant F ...] [--vitrine F ...] [-o OUT]` | build a case file from REVENANT/VITRINE JSON |

Weight kinds: `ip, domain, file_hash, imphash, tlsh, code_reuse, family, ttp, victimology, rich_header,
language, mutex, tool, ttp_profile`; values must be in [0, 1]. Markdown reports print every weight in a
Weights table and mark overridden ones; JSON reports list them under `weights`.

Exit status: 0 success, 2 usage or input error (one line on stderr, also for a missing optional
extra), 1/3 as above for `verify`.

Scripts: `scripts/download_data.py` (pinned, checksummed downloads), `scripts/run_benchmarks.py`
(all benchmarks, writes `results/` and `docs/figures/`; `--render-only` re-renders them from
`results/benchmark.json`), `scripts/compare_results.py` (the bench reproducibility gate),
`scripts/build_demo_pages.py` (this site's demo reports), `scripts/check_mermaid.mjs` (diagram parse check).
