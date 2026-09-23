"""Guard against version drift between pyproject.toml and guard_agent._version.

The 3.0.1 release shipped with pyproject.toml at 3.0.1 while _version.py
(the value reported as agent_version in telemetry batches and the User-Agent)
still said 3.0.0, because the release only hand-edited pyproject.toml instead
of running the bump script. This test fails if the two ever diverge again.
"""

from __future__ import annotations

import re
from pathlib import Path

from guard_agent._version import __version__

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_version_matches_version_module() -> None:
    pyproject = PROJECT_ROOT / "pyproject.toml"
    content = pyproject.read_text()
    match = re.search(r'^version\s*=\s*"([^"]*)"', content, re.MULTILINE)
    assert match is not None, "pyproject.toml has no version field"
    assert match.group(1) == __version__, (
        f"pyproject.toml version {match.group(1)!r} does not match "
        f"guard_agent._version.__version__ {__version__!r}; run "
        f"'make bump-version VERSION=x.y.z' instead of hand-editing"
    )
