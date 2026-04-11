import pytest
from pathlib import Path


@pytest.fixture
def fixtures_dir():
    """Return path to test fixtures directory."""
    return Path(__file__).parent.parent.parent / "tests" / "fixtures" / "scanner-outputs"


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Return a temporary output directory."""
    output = tmp_path / "argus-results"
    output.mkdir()
    return output
