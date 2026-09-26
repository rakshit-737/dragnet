# DRAGNET Threat Model

## Assets
- Integrity of the evidence and of the custody log
- Correctness and calibration of the attribution output
- The campaign knowledge graph

## Trust boundaries
1. Evidence JSON files come from REVENANT/VITRINE or an analyst. They are treated as untrusted input.
2. The knowledge-graph JSON is analyst-curated and trusted only to the extent of its provenance.
3. Reports go to human analysts.

## Threats and mitigations (STRIDE-style)

| Threat | Example | Mitigation (MVP) | Gap / TODO |
|---|---|---|---|
| **Adversarial false flag** (primary) | Attacker plants a Rich header, locale strings or mutexes tied to another actor | Forgeable kinds are low-weight and cannot attribute alone. Rule-based false-flag indicators. Mandatory `FALSE_FLAG` hypothesis. Confidence withheld when it leads | Deeper forgery checks, e.g. Rich-header vs. linker consistency |
| Evidence tampering | Evidence changed after ingestion | Per-item SHA-256 plus a hash-chained custody log with `verify()` | Log is unsigned. No external timestamping |
| Overconfidence / analyst anchoring | Single code-similarity hit read as proof | Noisy-OR caps any single signal. HIGH requires at least 2 hard kinds and a margin. "Raise/lower confidence" guidance | Calibration not yet measured (Brier) |
| KG poisoning | Wrong or fabricated campaign IOCs | JSON is reviewed and version-controlled | Per-edge provenance and source reliability grading |
| Shared infrastructure | CDN or VPS IP overlap misread as actor link | Listed under "lower confidence" guidance | Automated shared-hosting and sinkhole enrichment |
| Malicious input files | Oversized or malformed JSON | Strict schema checks (`IngestError`), stdlib `json` only, no code execution, no sample execution | Size limits |
| Information disclosure | Reports leak victim data | Synthetic fixtures only, no real victim data | Redaction pass |

## Out of scope
Live malware handling (SPECIMEN lab), network enrichment, and any offensive or "hack-back" use.
