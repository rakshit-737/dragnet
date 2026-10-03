"""The bench reproducibility gate (scripts/compare_results.py) must fail on any drift."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("compare_results", ROOT / "scripts" / "compare_results.py")
cr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cr)

BASE = {
    "A1": {"main": [{"method": "dragnet", "top1": 0.4}, {"method": "code-only", "top1": 0.3}]},
    "G": {"ours": {"dragnet": {"mean_rank": 5.38, "sd": 0.79}}},
    "C": {"time-of-incident": [{"case": "wannacry_2017", "leading": "Lazarus Group", "confidence": "MEDIUM"}]},
    "D": {"level2_ff_effect": {"mean_reduction": 0.228, "ci95_case_cluster": [0.11, 0.37]}},
    "F": {"ATT&CK aliases only": {"fisher_p_zero_vs_some": 0.007}},
    "B": {"B1": [{"method": "dragnet", "top1": 0.4}], "B3": {"x": 1}},
    "E2": {"seconds": 12.0, "x": 1},
    "provenance": {"sections_run": ["A1", "G", "C", "D", "F", "B", "E2"]},
}


def _run(tmp_path, new) -> int:
    (tmp_path / "old.json").write_text(json.dumps(BASE))
    (tmp_path / "new.json").write_text(json.dumps(new))
    return cr.main(str(tmp_path / "old.json"), str(tmp_path / "new.json"))


def test_identical_results_pass(tmp_path):
    assert _run(tmp_path, BASE) == 0


@pytest.mark.parametrize("path, value", [
    (("G", "ours", "dragnet", "mean_rank"), 99.0),
    (("D", "level2_ff_effect", "mean_reduction"), 0.0),
    (("F", "ATT&CK aliases only", "fisher_p_zero_vs_some"), 0.9),
    (("C", "time-of-incident", 0, "leading"), "Sandworm Team"),
])
def test_any_perturbed_value_fails(tmp_path, path, value):
    new = copy.deepcopy(BASE)
    node = new
    for k in path[:-1]:
        node = node[k]
    node[path[-1]] = value
    assert _run(tmp_path, new) == 1


def test_rows_are_matched_by_method_not_position(tmp_path):
    new = copy.deepcopy(BASE)
    new["A1"]["main"].reverse()
    assert _run(tmp_path, new) == 0


def test_live_parts_and_runtime_are_not_compared(tmp_path):
    new = copy.deepcopy(BASE)
    new["B"]["B3"]["x"] = 2
    new["E2"]["x"] = 2
    assert _run(tmp_path, new) == 0


def test_extra_or_missing_keys_fail(tmp_path):
    new = copy.deepcopy(BASE)
    new["G"]["ours"]["dragnet"]["top1"] = 0.5
    assert _run(tmp_path, new) == 1


def test_empty_section_fails(tmp_path):
    new = copy.deepcopy(BASE)
    new["G"] = {}
    old = copy.deepcopy(BASE)
    old["G"] = {}
    (tmp_path / "old.json").write_text(json.dumps(old))
    (tmp_path / "new.json").write_text(json.dumps(new))
    assert cr.main(str(tmp_path / "old.json"), str(tmp_path / "new.json")) == 1
