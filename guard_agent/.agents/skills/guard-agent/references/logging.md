# Logging

guard-agent logs on the `guard_agent` logger tree (`guard_agent`, `guard_agent.client`, `guard_agent.buffer`, ...). Every record carries the origin prefix `[<logger name>]`, so agent lines are identifiable in a host's log stream.

## What runs automatically

Constructing a `GuardAgentHandler` or `SyncGuardAgentHandler` calls `setup_agent_logging(reconfigure=False)`. That call is non-destructive:

* If the `guard_agent` logger already has handlers (host-configured logging), nothing is attached and nothing is changed; records flow to the host handlers via propagation.
* If it is unconfigured, one `StreamHandler` is attached with the standard guard-core formatter (`[guard_agent.client] 2026-09-01 12:00:00 - WARNING - ...`) and the logger level is set to `INFO` only if it is still `NOTSET`.
* A console handler is attached only when the root logger has no handlers (yield-to-host contract, same as guard-core); otherwise records propagate to the root.

The setup is idempotent: constructing the handler many times attaches at most one console handler and never removes host handlers or resets host levels.

## Explicit setup

Hosts that want the agent's own sink call `setup_agent_logging` (exported from `guard_agent`) directly. This reconfigures: it clears agent handlers first, then applies the requested configuration.

```python
from guard_agent import setup_agent_logging

setup_agent_logging(log_file="guard_agent.log", log_format="json")
```

* `log_format="json"` emits one record per line as `{"timestamp", "level", "logger", "message"}`; the default `"text"` emits the prefixed console format.
* `log_file=...` adds a `FileHandler` alongside the console handler.
* `reconfigure=False` (the default for explicit calls) applies only when the logger is unconfigured; pass `reconfigure=True` to force the clear-and-apply behavior.

## Notes

* Levels: the agent never raises a level the host set. Pass `logging.WARNING` on the `guard_agent` logger to quiet records without touching the agent.
* The old async `setup_agent_logging` stub that briefly lived in `guard_agent.utils` is gone; the implementation is `guard_agent.logging_utils.setup_agent_logging`.
