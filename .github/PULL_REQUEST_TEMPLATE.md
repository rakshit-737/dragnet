## What and why

## Checklist
- [ ] `python -m pytest -q` passes
- [ ] `python -m ruff check .` passes (ruff version pinned in `[dev]`)
- [ ] No datasets, malware binaries, keys or files over 1 MB added
- [ ] If scoring or protocols changed: results regenerated (`scripts/run_benchmarks.py` or the bench workflow) and README/docs numbers updated
- [ ] CHANGELOG `[Unreleased]` updated
