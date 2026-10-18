# Isolation implementation boundary

ModelBoundary Lab v0.6.0 separates **observations**, **static artifact findings**, and **inference smoke results**. It does not currently create or enforce an operating-system sandbox.

## What the tool can observe

- Linux `/proc/<pid>/status` values including `NoNewPrivs`, `Seccomp`, `CapEff`, and process identity.
- Namespace inode links and cgroup membership visible to the invoking user.
- Static model-directory files, modes, symlinks, JSON metadata, and SHA-256 hashes.
- Optional local/pinned model inference and deterministic output-hash comparisons.

## What observations do not prove

- Namespace IDs do not prove policy correctness or resource separation.
- `Seccomp: 2` means a filter is attached, not that the filter is sufficient.
- `NoNewPrivs: 1` does not confine filesystem or network access.
- Empty effective capabilities do not establish complete least privilege.
- File hashes establish identity of observed bytes, not trusted provenance.
- `trust_remote_code=False` and `use_safetensors=True` reduce specific risks, but do not prove absence of dependency/runtime vulnerabilities.
- A process running under the same Unix UID may still read files permitted to that UID. File permissions cannot protect against a privileged host administrator who controls the kernel and process memory.

## Requirements for a future enforced runner

Before claiming sandbox enforcement, a separate execution backend must apply and verify all required controls before loading any model:

1. Dedicated unprivileged UID/GID and a private model/runtime mount tree.
2. A verified mount namespace with read-only root and narrowly scoped writable output directory.
3. Network namespace with no external interfaces by default, and explicit policy for loopback or approved endpoints.
4. `no_new_privs`, dropped capabilities, and a reviewed seccomp profile appropriate for the runtime.
5. Landlock or another independently validated filesystem access policy where available.
6. Cgroup CPU, memory, process-count, and I/O bounds, plus wall-clock termination from a supervising parent.
7. File descriptor and environment allowlists; do not pass unrelated secrets or tokens to the child.
8. Tests that verify controls from both inside and outside the boundary, including negative access tests.
9. A documented adversary model and limitations for same-UID peers, kernel exploits, physical access, and administrators.
10. A signed build/provenance story and independently reviewed profiles.

Each control must report `APPLIED_AND_VERIFIED`, `NOT_APPLIED`, `INCONCLUSIVE`, or `NOT_SUPPORTED`, supported by evidence. A requested control is not evidence that it was applied.

## Current Bubblewrap profile

Version 0.6 adds an opt-in-by-default Bubblewrap runner for local model directories. It requires a preflight run and aborts before loading the model if Bubblewrap or required namespace options are unavailable. Its profile hides the host home/general data directories, binds the chosen model tree read-only, clears inherited environment variables, isolates network namespace, and enables no-new-privileges. It still does not apply cgroup resource budgets or a reviewed seccomp syscall policy, and its namespace observations are partial evidence, not a proof against kernel or runtime vulnerabilities. Do not use this profile against a threat model requiring strong protection from a compromised kernel, root administrator, or untrusted host.
