# Case file format

```json
{"case_id": "incident-7",
 "evidence": [
   {"id": "host-1", "kind": "forensic", "content": {"network_connections": ["203.0.113.7"],
     "dns_queries": ["evil.example"], "ttps": ["T1486"], "tools": ["psexec"]}},
   {"id": "sample-1", "kind": "malware", "content": {"sha256": "...", "imphash": "...",
     "family": "WannaCry", "rich_header": "...", "ttps": ["T1490"]}}]}
```

| kind | accepted fields -> signal kind |
|---|---|
| `forensic` | `network_connections` (ip), `dns_queries` (domain), `dropped_file_hashes` (file_hash), `ttps`, `mutexes`, `victimology`, `tools`, `language_artifacts` |
| `malware` | `sha256` (file_hash), `imphash`, `code_reuse`, `family`, `ttps`, `rich_header`, `language_artifacts`, `c2` (domain), `c2_ips` (ip), `mutexes`, `tools` |

Each evidence item's content is SHA-256 hashed (canonical JSON) and recorded in the custody chain on
ingest. Malware evidence is a *feature record*, never a binary.

## Adapters

`dragnet import` builds this file from sibling-tool exports:

- **REVENANT** export JSON: techniques from stories and events, public IPs and domains from event
  objects (`ip:`, `domain:`, `dns:`, `url:`), non-stock process images as tools. RFC 1918 / loopback
  addresses are dropped. Anti-forensics (tampering) indicators are kept as `analyst_context`.
- **VITRINE** triage JSON: sha256, family, ATT&CK capability ids and, when present, imphash, Rich
  header, C2 and mutexes.
