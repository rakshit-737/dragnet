"""Filesystem locations. Datasets live OUTSIDE the repo (never committed)."""
from __future__ import annotations

import os
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
REPO = PACKAGE.parent
#: True when running from a source checkout (scripts/ next to the package).
IN_CHECKOUT = (REPO / "scripts" / "download_data.py").is_file()


def _fixtures() -> Path:
    """$DRAGNET_FIXTURES, else the bundled package data (synthetic KG, demo and real cases)."""
    env = os.environ.get("DRAGNET_FIXTURES")
    return Path(env) if env else PACKAGE / "data"


FIXTURES = _fixtures()
RESULTS = REPO / "results"


def data_dir() -> Path:
    """Raw public datasets: $DRAGNET_DATA; in a checkout ../../datasets/dragnet if present, else
    ./data/raw of the checkout; for an installed package a per-user cache directory."""
    env = os.environ.get("DRAGNET_DATA")
    if env:
        return Path(env)
    if IN_CHECKOUT:
        sibling = REPO.parent.parent / "datasets" / "dragnet"
        return sibling if sibling.exists() else REPO / "data" / "raw"
    base = os.environ.get("XDG_CACHE_HOME") or os.environ.get("LOCALAPPDATA") or str(Path.home() / ".cache")
    return Path(base) / "dragnet"


def download_hint() -> str:
    """How to obtain the public datasets from where we are running."""
    if IN_CHECKOUT:
        return "run: python scripts/download_data.py"
    return ("clone https://github.com/rakshit-737/dragnet and run scripts/download_data.py, "
            "then point $DRAGNET_DATA at the download directory")
