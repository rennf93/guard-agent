# fastapi-guard-agent (deprecated alias)

> **This package has been renamed to [`guard-agent`](https://pypi.org/project/guard-agent/).**

As of `guard-agent` 2.0.0, the telemetry agent previously distributed under the name `fastapi-guard-agent` has been repositioned as a framework-agnostic agent serving `fastapi-guard`, `flaskapi-guard`, `djangoapi-guard`, and `tornadoapi-guard`.

This PyPI entry (`fastapi-guard-agent==1.2.0`) is a meta-package: installing it transitively installs `guard-agent>=2.0.0,<3.0.0`. It exists so that existing install commands referencing `fastapi-guard-agent` in scripts, Dockerfiles, and lockfiles continue to resolve to the renamed distribution.

## Migration

The Python import path has **not** changed:

```python
from guard_agent import GuardAgentHandler, AgentConfig  # still works
```

Only the install command needs updating at your leisure. With uv:

```bash
# Old (still works via this meta-package)
uv add fastapi-guard-agent

# Preferred going forward
uv add guard-agent
```

Equivalent in other package managers:

```bash
# Poetry
poetry remove fastapi-guard-agent && poetry add guard-agent

# pip
pip uninstall fastapi-guard-agent && pip install guard-agent
```

## Links

- **Product site:** <https://guard-core.com>
- **Dashboard:** <https://app.guard-core.com>
- **Playground:** <https://playground.guard-core.com>
- **New package on PyPI:** <https://pypi.org/project/guard-agent/>
- **Repository:** <https://github.com/rennf93/guard-agent>
- **Documentation:** <https://rennf93.github.io/guard-agent/>
- **CHANGELOG (v2.0.0 rename notes):** <https://github.com/rennf93/guard-agent/blob/master/CHANGELOG.md>
