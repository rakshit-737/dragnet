# REST API

Optional FastAPI service: `pip install -e ".[api]"` then `python -m dragnet serve --kg KG.json`
(binds to 127.0.0.1 by default; interactive docs at `/docs`). With Docker: `docker compose up api`.

| Method | Path | Body / query | Returns |
|---|---|---|---|
| GET | `/health` | - | status, number of actors, KG metadata |
| GET | `/actors` | - | actors with ATT&CK id and suspected sponsor state |
| POST | `/assess` | case JSON; `?format=json` (default) or `?format=stix` | assessment JSON or STIX 2.1 bundle |

Invalid case files return HTTP 422 with the ingest error. The API has no authentication: it is meant
for a lab or analyst workstation, not the internet (see [Security](../security.md)).

```bash
curl -s -X POST localhost:8000/assess -H 'content-type: application/json' \
     -d @fixtures/cases/wannacry_like.json | jq .leading
```
