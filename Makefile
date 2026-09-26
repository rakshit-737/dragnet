PY ?= python

.PHONY: install data bench demo test lint kg

install:
	$(PY) -m pip install -e ".[dev,api,bench]"

data:            ## download public datasets (~300 MB) into $$DRAGNET_DATA
	$(PY) scripts/download_data.py

kg:              ## build the real knowledge graph JSON
	$(PY) -m dragnet build-kg

bench:           ## run every benchmark, write results/ and docs/figures/
	$(PY) scripts/run_benchmarks.py

demo:            ## synthetic scenarios + real case studies (if data present)
	$(PY) -m dragnet demo
	$(PY) -m dragnet assess fixtures/cases/olympic_destroyer_like.json
	-$(PY) -m dragnet case-study

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .
