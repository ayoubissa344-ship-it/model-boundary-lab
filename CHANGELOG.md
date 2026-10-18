# Changelog

## 0.6.0 — 2026-10-18
- Added installable `mbl` CLI and dependency-free local dashboard.
- Added static model artifact audit with SHA-256 fingerprints, custom-code and pickle-format warnings, file-permission checks, and escaping-symlink detection.
- Added `/proc` process inspection and runtime namespace/control telemetry with explicit `NOT_ESTABLISHED` security status.
- Added optional Transformers inference smoke tests, deterministic-repeatability records, declarative JSONL regression checks, prompt hashing, output redaction, and wall-clock supervision.
- Added an opt-in, fail-closed Bubblewrap profile for local models: separate user/mount/PID/network/IPC/UTS namespaces, a minimal read-only model/runtime view, and no inherited environment secrets. The profile is reported as partial control evidence, not a complete sandbox guarantee.
- Added explicit immutable-SHA resolution for public Hub model metadata and candidate models for future tests.
- Expanded Python unit coverage; fixed a floating-point edge case in the TypeScript Wilson interval; added minimal offline TypeScript declarations so its checks run without a network install.
- No real pretrained model inference was performed in the release environment; all model inference statuses remain `NOT_RUN` until a user runs the tool with model weights and dependencies available.

## 0.5.0
- Added Zenodo DOI reference supplied by the project author.
- Added dependency-free Python package-integrity tests and Hugging Face integration notes.
- No real-model inference or security-enforcement result was claimed.

## 0.4.0
- C++ observational process probe, TypeScript evidence validator, Rust preflight prototype, and optional local model smoke-test runner.
