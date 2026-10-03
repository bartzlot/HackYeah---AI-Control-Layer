import shutil
from pathlib import Path

import pytest

from aicl_core import Engine

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "policy" / "policy.yaml"


@pytest.fixture(scope="session")
def engine():
    return Engine(POLICY)


@pytest.fixture
def policy_dir(tmp_path):
    """A private copy of policy/ (policy.yaml, rules/, local.d/) for reload tests."""
    d = tmp_path / "policy"
    shutil.copytree(REPO / "policy", d)
    for f in (d / "local.d").glob("*.yaml"):
        f.unlink()
    pol = d / "policy.yaml"
    # rule_files are resolved from the repo root (= policy dir's parent): mirror the layout
    return pol
