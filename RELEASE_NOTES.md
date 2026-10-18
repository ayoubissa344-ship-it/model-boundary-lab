# ModelBoundary Lab — Release Candidate

This release candidate focuses on evidence-driven process-isolation
engineering: a Rust seccomp probe, explicit security boundaries,
reproducible tests, and automated CI.

### Validation
Run `bash scripts/release-check.sh`.

### Security status
The seccomp probe is not a complete sandbox. Filesystem isolation, network
isolation, and enforcement of policy on the model runtime remain unverified.
Do not use this release as a security boundary for hostile workloads.
