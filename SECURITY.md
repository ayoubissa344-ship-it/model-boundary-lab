# Security policy

## Safe use

ModelBoundary Lab is an auditing and evaluation tool, not a sandbox. Do not load models or artifacts from sources you do not trust. Static audits do not make subsequent model loading safe.

- The inference runner sets `trust_remote_code=False` and `use_safetensors=True`.
- Remote model downloads are disabled unless explicitly enabled and pinned to a full commit SHA.
- The dashboard binds to loopback only and rejects non-loopback bind addresses. Do not expose it with a reverse proxy, tunnel, or LAN bind without adding authentication and a reviewed threat model.
- Inference executes in a supervised child process with a timeout. Child-process separation is not kernel-enforced isolation.
- Prompts are represented in reports by SHA-256, not stored verbatim. Generated text is included by default; select output redaction for sensitive evaluation.
- Never commit Hub tokens, model weights, private prompts, or unredacted reports.

## Report a vulnerability

Please provide a reproducible description, affected version, impact, and minimal safe reproduction. Do not include secrets or other people's private model artifacts.
