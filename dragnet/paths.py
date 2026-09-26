"""Filesystem locations. Datasets live OUTSIDE the repo (never committed)."""
from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"
RESULTS = REPO / "results"


def data_dir() -> Path:
    """Raw public datasets: $DRAGNET_DATA, else ../../datasets/dragnet, else ./data/raw."""
    env = os.environ.get("DRAGNET_DATA")
    if env:
        return Path(env)
    sibling = REPO.parent.parent / "datasets" / "dragnet"
    if sibling.exists():
        return sibling
    return REPO / "data" / "raw"
