# Experimental protocol v1.0

## 1. Pre-register the question
Write one falsifiable question and distinguish observation from enforcement. Example: “Does this test process run with the expected namespace identifiers under configuration X?” This is not equivalent to “the model weights are confidential.”

## 2. Define the adversary
Record identity/UID, capabilities, access to `/proc`, filesystem, ptrace, kernel, host admin, and ability to execute code in the serving process. State exclusions.

## 3. Freeze the environment
Record OS/kernel, architecture, container runtime, compiler versions, exact source commit, model repository ID, full immutable model revision, model license, and SHA-256 of experiment scripts.

## 4. Run controls
Run a baseline without the intended control, then the controlled condition. Keep output raw. Never run hostile tests against systems outside the authorized lab.

## 5. Trial design
Predefine repetitions, randomization, inclusion/exclusion criteria, and independence rationale. Repeated runs on the same host are not automatically independent.

## 6. Status vocabulary
- `PASS`: named check met its predeclared criterion.
- `FAIL`: named check violated criterion.
- `INCONCLUSIVE`: evidence insufficient or ambiguous.
- `SKIP`: check intentionally not run.
- `NOT_RUN`: no execution occurred.

## 7. Reporting
Publish methods, artifacts, hashes, environment, missing data, limitations, and negative results. Do not infer confidentiality from absence of an observed leak. Do not infer enforcement from reading configuration alone.
