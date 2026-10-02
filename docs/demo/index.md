# Demo reports

Static reports for the synthetic spec scenarios in `dragnet/data/cases/`, assessed against the
synthetic knowledge graph `dragnet/data/campaigns.json` (no downloads needed). Regenerate with
`python scripts/build_demo_pages.py`. Each report also has a STIX 2.1 bundle.

| scenario | verdict | confidence | false-flag indicators | STIX |
|---|---|---|---|---|
| [multi_signal_boost](multi_signal_boost.md) | SANDWORM_SIM | HIGH | 0 | [bundle](multi_signal_boost.stix.json) |
| [olympic_destroyer_like](olympic_destroyer_like.md) | withheld | INSUFFICIENT | 2 | [bundle](olympic_destroyer_like.stix.json) |
| [thin_evidence](thin_evidence.md) | withheld | INSUFFICIENT | 0 | [bundle](thin_evidence.stix.json) |
| [wannacry_like](wannacry_like.md) | LAZARUS_SIM | HIGH | 0 | [bundle](wannacry_like.stix.json) |

Real-data case studies (WannaCry, NotPetya, Olympic Destroyer, ...) need the downloaded
datasets; their results are on the [benchmarks page](../benchmarks.md).
