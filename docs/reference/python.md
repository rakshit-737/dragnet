# Python API

The runtime is stdlib-only. The main entry points:

```python
from dragnet.graph import KnowledgeGraph
from dragnet.ingest import load_case
from dragnet.ach import assess
from dragnet.report import to_markdown
from dragnet.stix import to_stix

kg = KnowledgeGraph.load("fixtures/campaigns.json")
case_id, items, signals, custody = load_case("fixtures/cases/wannacry_like.json")
a = assess(case_id, signals, kg, custody=custody)
print(a.leading, a.confidence.value)
```

::: dragnet.ach.assess

::: dragnet.ingest.load_case

::: dragnet.ingest.build_case

::: dragnet.models.Assessment

::: dragnet.custody.CustodyLog

::: dragnet.custody.sign_entries

::: dragnet.custody.verify_signed

::: dragnet.stix.to_stix

::: dragnet.adapters.from_revenant

::: dragnet.adapters.from_vitrine

::: dragnet.bench.bootstrap_ci

::: dragnet.bench.paired_bootstrap_diff
