# ModelBoundary Lab Architecture

## Objective
ModelBoundary Lab is a fail-closed process-isolation research project.
It separates portable policy decisions from operating-system enforcement
and independent verification.

## Components

1. Policy core
   - Parses the declared security profile.
   - Defines required controls and expected behavior.
   - Rejects claims that exceed verified capabilities.

2. Platform capability discovery
   - Reports which enforcement primitives are available.
   - Distinguishes unavailable, unsupported, failed, and verified controls.
   - Treats capability discovery as evidence, not proof of isolation.

3. Enforcement backends
   - Linux: seccomp and supported kernel isolation primitives.
   - Android: Android application and kernel restrictions, subject to
     the actual app identity and device policy.
   - Windows and macOS: future backends requiring platform-specific
     implementations and independent tests.

4. Verification engine
   - Exercises allowed and forbidden operations.
   - Records expected and observed outcomes.
   - Never treats a missing test as a passing test.

5. Runtime integration
   - Must launch the actual target process under the selected policy.
   - Must verify that the policy applies to the target and its children.
   - A standalone probe is not proof that a model runtime is isolated.

## Current implementation boundary

The current Rust seccomp probe denies a selected syscall and tests the
filter behavior. It is not a comprehensive syscall allowlist, filesystem
sandbox, network sandbox, or cross-platform isolation engine.

The project must report SANDBOX_STATUS=NOT_ESTABLISHED until all required
controls for the requested profile are independently verified.
