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

| Threat | Example | Mitigation | Gap / TODO |
|---|---|---|---|
| **Adversarial false flag** (primary) | Attacker plants a Rich header, locale strings or mutexes tied to another actor | Forgeable kinds are low-weight and cannot attribute alone. Rule-based false-flag indicators. Mandatory `FALSE_FLAG` hypothesis. Confidence withheld when it leads | Deeper forgery checks, e.g. Rich-header vs. linker consistency |
| Evidence tampering | Evidence changed after ingestion | Per-item SHA-256, hash-chained custody log, optional Ed25519 signature over the head (`keygen`, `assess --sign-key`, `verify --pub`) | Key management; no external timestamping |
| Overconfidence / analyst anchoring | Single code-similarity hit read as proof | Noisy-OR caps any single signal; specificity weighting; HIGH requires 2 anchor kinds and a margin. "Raise/lower confidence" guidance. Calibration measured (Brier/ECE, accuracy per grade) in `results/RESULTS.md` | Raw scores are not calibrated; an isotonic map is evaluated on a temporal split (section R) |
| KG poisoning | Wrong or fabricated campaign IOCs | Graph built only from pinned, checksummed public sources (ATT&CK, MISP galaxy) plus manifest-recorded abuse.ch snapshots; every curated `kg_additions` edge cites a source | No per-edge source-reliability grading |
| Feed pollution | Shared packer / .NET-stub imphashes or commodity IOCs pulling in unrelated actors | Imphash collision filter (> 2 families dropped); specificity weighting; min ThreatFox confidence | Commodity malware attributed by ATT&CK to a few groups still links |
| Shared infrastructure | CDN or VPS IP overlap misread as actor link | Listed under "lower confidence" guidance | Automated shared-hosting and sinkhole enrichment |
| Malicious input files | Oversized or malformed JSON | Strict schema checks (`IngestError`), API body and evidence-count limits (413/422), stdlib `json` only, no sample execution | Streaming parse for very large offline cases |
| Information disclosure | Reports leak victim data | Fixtures contain only public IOCs/metadata of documented incidents, no victim data | Redaction pass |
| Malicious dataset download | Tampered upstream file | Pinned SHA-256 for ATT&CK/MISP/APTnotes; zip/JSON structural validation; metadata only, nothing executed | abuse.ch exports cannot be pinned (daily) |

## Out of scope
Live malware handling (SPECIMEN lab), network enrichment, and any offensive or "hack-back" use.
