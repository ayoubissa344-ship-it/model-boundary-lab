# ModelBoundary Lab v0.6.0

**A local-first CLI and dashboard for auditing model artifacts, observing Linux process-isolation signals, and running reproducible local LLM smoke/regression tests.**

- **Research record:** [10.5281/zenodo.23442798](https://doi.org/10.5281/zenodo.23442798) (provided by the project author; verify the record metadata before citing).
- **Implementation:** Python CLI + loopback dashboard, optional Transformers inference backend, C++ process probe, TypeScript evidence validator, and Rust preflight prototype.
- **Security claim boundary:** this release does **not** create a kernel-enforced sandbox and does **not** prove model-weight confidentiality.

## What it does today

### 1. Static model artifact audit

`mbl audit-model ./model` hashes observed files and reports legacy pickle-capable extensions, custom `auto_map` declarations, Python source files, symlinks escaping the model tree, world-writable files, missing config, and whether `.safetensors` artifacts were observed. It does not deserialize the model or execute model code. Findings are heuristics, not a definitive malware verdict.

### 2. Runtime and process inspection

`mbl doctor` captures the invoking process's namespace identifiers, `NoNewPrivs`, Seccomp mode, effective capabilities, cgroup membership, available sandbox utilities, and optional package versions. `mbl inspect-pid PID` captures a read-only `/proc` snapshot for an authorized process. These are observations, not a security score.

### 3. Local or pinned model inference

The optional backend uses Transformers in a supervised child process with a wall-clock timeout, disables `trust_remote_code`, and requests `safetensors` weights. It can run deterministic greedy-generation repetitions and record output hashes, load/inference timings, token counts, and model/runtime metadata. It never stores the prompt text in reports; it stores prompt hashes. Generated output is included by default and can be redacted.

**The default requires a Bubblewrap preflight.** When `bwrap` and user namespaces work, the local-only profile creates separate user/mount/PID/network/IPC/UTS namespaces, exposes the selected model directory read-only, hides the host home and general data folders, clears the child environment, and enables `NoNewPrivs`. It is a constrained execution profile, not a complete or independently certified sandbox; resource cgroups and a reviewed seccomp profile are not yet enforced. If the preflight is unavailable, the run stops before model loading. `--sandbox off` is an explicit opt-out for environments without Bubblewrap.

Hub downloads require the explicit `--allow-network` flag and a full immutable model commit SHA. Network-enabled loading is incompatible with the required network-isolated profile, so resolve/download the pinned snapshot first, audit the local directory, and run that directory in the required profile; use `--sandbox off` only when you knowingly choose direct network-enabled execution.

### 4. JSONL regression suite

A suite case has `id`, `prompt`, and optional declarative checks (`contains`, `equals`, `valid_json`). No test-provided code or regular expressions are evaluated. A sample suite is included at `examples/smoke-suite.jsonl`.

## Install

Python 3.10 or newer is required for the CLI. The base auditor uses only the Python standard library.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
```

To enable the real local-model backend, install the optional dependencies in an environment with internet access or a prepared wheelhouse:

```bash
python -m pip install '.[inference]'
```

On Android/Termux, compatibility of PyTorch, Transformers, and individual model architectures depends on the installed Python/build environment. The static auditor and process telemetry remain useful without those inference dependencies.

## Quick start

### Inspect the environment

```bash
mbl doctor --out runs/doctor.json
mbl inspect-pid $$ --out runs/current-process.json
```

### Audit a downloaded model directory without loading it

```bash
mbl audit-model /path/to/model --out runs/model-audit.json
```

For faster metadata-only scans of very large model directories, omit per-file hashing:

```bash
mbl audit-model /path/to/model --no-hash
```

### Run a local model

```bash
mbl run-model /path/to/local/model \
  --prompt-file examples/prompt.txt \
  --sandbox required --trials 2 --max-new-tokens 32 --out-dir runs
```

A successful command reports `PASS_SMOKE_ONLY`, never `PROVEN_SECURE`.

### Resolve a public model to an immutable revision

```bash
mbl resolve-model HuggingFaceTB/SmolLM2-135M-Instruct --allow-network --out runs/model-pin.json
```

This reads public metadata only. Review the model card/license and output SHA. Then download a pinned snapshot using your normal approved Hub tooling, audit the local folder, and run it with the default Bubblewrap profile. The included API resolver does not download model weights.

Example pinned download and local run (requires the `hf` CLI, a working network connection during download, and Bubblewrap support for required-mode inference):

```bash
REV=$(python -c 'import json; print(json.load(open("runs/model-pin.json"))["revision"])')
hf download HuggingFaceTB/SmolLM2-135M-Instruct --revision "$REV" --local-dir models/SmolLM2-135M-Instruct
mbl audit-model models/SmolLM2-135M-Instruct --out runs/smol-audit.json
mbl run-model models/SmolLM2-135M-Instruct \
  --prompt-file examples/prompt.txt --sandbox required \
  --trials 2 --max-new-tokens 32 --redact-output --out-dir runs
```

The example is a reproducible recipe, not a claim that this model was already run in the release environment. If Bubblewrap is unavailable, required mode stops before model loading. `--sandbox off` permits a direct child-process smoke test but explicitly provides no OS confinement.

The included `models/evaluation-candidates.json` lists two candidate models that were inspected at metadata level, but **neither was run during release validation**. Never confuse metadata inspection with inference testing.

### Run the regression suite

```bash
mbl benchmark /path/to/local/model examples/smoke-suite.jsonl \
  --sandbox required --trials 1 --max-new-tokens 48 --out-dir runs
```

The included checks are basic behavioral smoke checks; they are not a benchmark leaderboard, safety certification, or security proof. A remote repo ID requires explicit `--allow-network`, a full revision SHA, and `--sandbox off`, or preferably a pre-downloaded local snapshot for the required profile.

### Launch the local dashboard

```bash
mbl serve --host 127.0.0.1 --port 8765 --runs-dir runs
```

Open `http://127.0.0.1:8765`. The dashboard supports environment inspection, model directory audits, process inspection, local model inference, and a recent-report index. It has no authentication and must stay on loopback.

## Report format and evidence handling

Every run writes JSON beneath `runs/`. Reports preserve status distinctions such as `PASS_SMOKE_ONLY`, `NOT_RUN`, `TIMEOUT`, and `INCONCLUSIVE`. Prompt strings are represented by SHA-256 hashes and are not stored in reports; generated output is stored by default, so enable `--redact-output` for sensitive experiments.

Before publishing a report, review absolute paths, process metadata, model identifiers, generated text, timings, and any metadata that could reveal private information.

## Current validation status

The project validation record is `BUILD_STATUS.json`; the test transcript is `TEST_RESULTS.txt`. Tests cover parser safety, static audit findings, symlink/permission findings, evidence-schema behavior, dashboard requests, and fail-closed sandbox handling. A real pretrained LLM inference was **not** executed during this release build because no model weights were cached, Transformers was absent, and the environment could not reach package/model downloads. No Hugging Face Jobs task was submitted because the connected account does not have the plan required for Jobs; no paid workload was started.

## Isolation requirements and limitations

See `docs/ISOLATION_REQUIREMENTS.md` for controls required before a future release may claim enforcement. In particular, `Seccomp: 2` alone is insufficient, `NoNewPrivs` is not a filesystem/network policy, and ordinary file permissions do not protect against privileged host access or necessarily against same-UID processes.

## License

See `LICENSE-RESEARCH.txt`. It is a custom non-commercial research license draft and is not OSI-approved. Third-party model weights, model code, datasets, and dependencies retain their respective licenses. Obtain legal review before relying on commercial-use restrictions.
