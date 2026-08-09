# logfire / Pydantic Plugin Mute

## Why

`SecurityEvent` and `SecurityMetric` are validated on every request, and `EventBatch` re-validates every buffered event on each flush. A host app that calls `logfire.instrument_pydantic()` (which instruments the Pydantic plugin) would otherwise emit a validation span per security event, potentially hundreds of thousands of spans per day under real traffic.

## What

At `guard_agent` import time, `_mute_pydantic_plugin_instrumentation()` sets:

```python
model.model_config["plugin_settings"]["logfire"] = {"record": "off"}
```

on `SecurityEvent`, `SecurityMetric`, and `EventBatch`, then calls `model.model_rebuild(force=True)` on each. `plugin_settings` is only read while building a model's validator, hence the forced rebuild.

## Properties

* No logfire import: the mute sets a Pydantic config value only; it works without logfire installed.
* Clean no-op if the models are not importable: an `ImportError` from `guard_agent.models` returns early.
* Survives rebuild failure: if `model_rebuild` raises, the exception is swallowed with a WARNING log on the `guard_agent` logger, leaving instrumentation on rather than crashing import.
* Idempotent: setting the same `plugin_settings` and re-rebuilding is harmless. guard-core applies the same mute to the same three models at `guard_core` import; importing both packages does not conflict.

## Host-App Implication

A consumer that calls `logfire.instrument_pydantic()` after `import guard_agent` will not emit per-event validation spans for the agent's telemetry models. Other Pydantic models in the host app remain instrumented. The mute is scoped to `SecurityEvent`, `SecurityMetric`, and `EventBatch` only.
