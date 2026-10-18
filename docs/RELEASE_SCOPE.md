# Release Scope

## Implemented and testable
- Rust seccomp probe for a selected syscall.
- Probe self-test and BPF instruction unit tests.
- Fail-closed reporting of the limits of the current environment.
- Security policy and reproducible local verification commands.

## Not yet established
- Comprehensive syscall restriction.
- Filesystem isolation with tested escape resistance.
- Network isolation with tested escape resistance.
- Resource limits and process-tree containment.
- Isolation of the actual llama.cpp model runtime.
- Equivalent enforcement backends for Windows, macOS, and Android.
- Independent security review.

## Release rule
Do not advertise this version as a production sandbox. Describe it as a
security-isolation prototype with a tested seccomp probe until the missing
controls are implemented and verified.
