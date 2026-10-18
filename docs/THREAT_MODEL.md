# Threat Model

## Assets
- Host files and credentials
- Network access
- Host processes and operating-system resources
- Model inputs, outputs, and model files
- Integrity of security evidence

## Threats
- A target process accesses files outside its permitted scope.
- A target process opens prohibited network connections.
- A child process escapes the intended policy.
- A syscall filter is incomplete or applied to the wrong process.
- Capability checks pass without enforcement actually being active.
- Reports overstate protection or omit failed tests.

## Security objectives
- Default to denial when a required control cannot be enforced.
- Keep policy evaluation separate from enforcement.
- Test negative cases, not only successful startup.
- Record exact platform, kernel, architecture, policy, and artifact hashes.
- Distinguish PASS, FAIL, UNSUPPORTED, and NOT_VERIFIED.

## Explicit non-goals of the current prototype
- Protection against every kernel exploit.
- A universal security boundary on every operating system.
- Complete filesystem or network isolation.
- Guaranteed safety of arbitrary untrusted native code.
- Proof that an external model runtime inherits the probe's restrictions.

## Assumptions
The host kernel and its enforcement mechanisms are part of the trusted
computing base. A userspace program cannot guarantee isolation if the host
does not provide an enforceable boundary.
