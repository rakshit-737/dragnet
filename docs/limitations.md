# Limitations and roadmap

## Limitations

- **Small n.** 25 attributed ATT&CK campaigns and 7 curated cases; bootstrap CIs are wide
  (DRAGNET top-1 0.68 [0.48, 0.84]) and the ablation differences (+0.08) are not significant.
- **Ground truth is itself attribution.** ATT&CK and government statements can be wrong or incomplete.
- **Residual leakage.** v19.2 group profiles were partly written from the same reporting as the
  campaigns; the temporal hold-out (A2) and time-of-incident mode reduce but do not remove this.
- **Curated tokens.** Where public evidence is a relationship (a copied Rich header, a shared function),
  curated cases use descriptive tokens with cited sources rather than raw artifacts.
- **Coarse sponsor-state and language signals** (MISP country); some "actor-specific" ATT&CK families
  are commodity malware.
- **Raw scores are under-confident**; use the discrete grade.
- **Zero confident errors is not a zero error rate**: 0/25 bounds the rate below ~12% (rule of three).
- **Adapters are file-based.** REVENANT / VITRINE integration reads their JSON exports; no live coupling.
- **Signing** proves integrity and (with a pinned key) signer identity; key management is out of scope.

## Not done, and why

| Item | Why it stays open |
|---|---|
| Fuzzy genetics (TLSH/ssdeep) | MalwareBazaar publishes TLSH, but a fair benchmark needs a distance index over ~500k samples with family-collision handling; not reported half-measured |
| Learned calibration | 25 + 7 labelled cases would overfit any fitted calibrator |
| Live sample handling | by design: DRAGNET never touches binaries; the spec's SPECIMEN lab needs isolated VMs |
| Ground-truth attribution judgment | needs human analysts; public attributions are used as-is |

## Roadmap

- [x] Real knowledge graph from ATT&CK + MISP + abuse.ch with provenance
- [x] Case-study validation and Brier/ECE; bootstrap CIs and paired tests
- [x] False-flag stress test (multi-seed), ablations
- [x] Neo4j export, FastAPI service, STIX 2.1 export, Ed25519-signed custody
- [x] REVENANT / VITRINE adapters
- [ ] Fuzzy genetics (TLSH distance)
- [ ] Learned monotone calibration on a larger curated case set
