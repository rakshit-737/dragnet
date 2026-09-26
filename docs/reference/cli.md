# CLI reference

`python -m dragnet <command>` (or the `dragnet` console script).

| Command | Purpose |
|---|---|
| `assess CASE [--kg KG] [--weight kind=w ...] [--format md\|json\|stix] [--sign-key KEY] [-o OUT]` | assess one case file |
| `demo [--kg KG]` | run the bundled synthetic scenarios |
| `build-kg [--attack-version 19.2] [--with-campaigns] [--data DIR] [-o OUT]` | build a knowledge graph from downloaded ATT&CK/MISP |
| `case-study [NAME] [--mode time-of-incident\|retrospective] [--format summary\|md\|json]` | curated real cases (needs data) |
| `export-cypher [--kg KG] [--case CASE] [-o OUT]` | Neo4j Cypher script |
| `serve [--kg KG] [--host 127.0.0.1] [--port 8000]` | optional FastAPI server |
| `keygen PREFIX` | Ed25519 key pair `PREFIX.key` / `PREFIX.pub` (needs `[sign]`) |
| `verify REPORT [--pub PUB]` | check the custody chain and, if present, its signature; exit 1 on failure |
| `import CASE_ID [--revenant F ...] [--vitrine F ...] [-o OUT]` | build a case file from REVENANT/VITRINE JSON |

Weight kinds: `ip, domain, file_hash, imphash, code_reuse, family, ttp, victimology, rich_header,
language, mutex, tool, ttp_profile`; values must be in [0, 1].

Scripts: `scripts/download_data.py` (pinned, checksummed downloads), `scripts/run_benchmarks.py`
(all benchmarks, writes `results/` and `docs/figures/`), `scripts/build_demo_pages.py` (this site's
demo reports).
