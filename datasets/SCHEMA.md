# Evidence dataset schema (v1)

Each JSONL record should include:

- `schema_version`: string, currently `1.0` for general experiment evidence, or a named MBL report schema.
- `experiment_id`: stable unique identifier.
- `timestamp_utc`: ISO-8601 UTC timestamp.
- `evidence_class`: `synthetic` or `observed`.
- `model_id`: repository identifier or `null`.
- `model_revision`: immutable commit SHA or `null`.
- `threat_model`: declared attacker capabilities.
- `controls`: exact controls and configuration.
- `checks`: list of `{name, status, detail}` with status `PASS`, `FAIL`, `INCONCLUSIVE`, or `SKIP`.
- `artifacts`: paths and SHA-256 values for retained raw outputs.
- `independent_trials`: boolean, with rationale in `independence_rationale`.
- `limitations`: array of known limitations.
- `status`: if present, distinguish `PASS_SMOKE_ONLY`, `NOT_RUN`, `SANDBOX_UNAVAILABLE`, `TIMEOUT`, and `INCONCLUSIVE` rather than collapsing them into one pass/fail bit.

Do not include access tokens, personal data, private prompts, secrets, or proprietary weights. By default, MBL stores prompt hashes rather than prompt content; generated output may be sensitive and can be redacted. `PASS` applies only to the named check, not to an overall security claim. Synthetic test fixtures must never be presented as observed model inference.
