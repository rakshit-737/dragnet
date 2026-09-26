PY ?= python

.PHONY: demo test install report

install:
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m dragnet demo
	$(PY) -m dragnet assess fixtures/cases/olympic_destroyer_like.json

report:
	$(PY) -m dragnet assess fixtures/cases/wannacry_like.json --format json -o wannacry_report.json
