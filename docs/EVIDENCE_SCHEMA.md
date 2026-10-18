# Evidence record conventions

All JSON reports emitted by ModelBoundary Lab include `schema_version`, `generated_at_utc`, `evidence_class`, a typed `assessment_type` where applicable, and an explicit `security_assessment.status`.

Allowed evidence classes:
- `observed`: directly read from the executing environment or runtime.
- `synthetic`: generated fixture/test data; never describe as a real model result.
- `derived`: a computed value with source evidence retained.

Important status conventions:
- `PASS_SMOKE_ONLY`: a model load/generation operation completed; no security claim follows.
- `NOT_RUN`: attempted execution did not reach a successful inference result.
- `TIMEOUT`: supervised execution exceeded its configured wall-clock limit.
- `INCONCLUSIVE`: evidence was incomplete or not interpretable.
- `NOT_ESTABLISHED`: security property was not proven by the available test.

The tool intentionally rejects `PROVEN_SECURE` as an accepted status. Report paths may contain absolute local paths; review and redact them before publishing reports. Raw prompt text is not stored by the tool, but generated output text is stored by default unless `--redact-output` is selected. Generated outputs can themselves contain sensitive information.
