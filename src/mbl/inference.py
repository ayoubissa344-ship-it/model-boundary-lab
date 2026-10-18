"""Opt-in local LLM smoke evaluation using Transformers.

Model loading is isolated from the parent CLI by a child process and a wall
clock timeout. Custom remote code is disabled and safetensors are required.
This is process separation for timeout/error handling, NOT a kernel sandbox.
"""
from __future__ import annotations
import json, os, socket, subprocess, sys, time, uuid
from pathlib import Path
from typing import Any
from .core import SCHEMA_VERSION, SHA_RE, audit_model_directory, json_dump_atomic, runtime_doctor, sha256_text, utc_now
from .sandbox import build_bwrap_command, probe_bwrap, verify_child_boundary

MAX_PROMPT_CHARS = 20_000
MAX_NEW_TOKENS = 128
MAX_CASES = 30


def _validate_model_source(model: str, revision: str | None, allow_network: bool) -> tuple[bool, bool]:
    if not model or len(model) > 512:
        raise ValueError("model must be a non-empty local path or Hub repo ID (<=512 chars)")
    local_dir = Path(model).expanduser()
    is_local = local_dir.exists()
    if is_local and not local_dir.is_dir():
        raise ValueError("local model path must be a directory")
    if not is_local:
        if not allow_network:
            raise ValueError("Hub model loading is disabled by default; pass --allow-network explicitly")
        if not revision or not SHA_RE.fullmatch(revision):
            raise ValueError("remote models require a full immutable commit SHA (40-64 hex characters)")
    return is_local, (allow_network and not is_local)


def run_prompts(
    model: str,
    prompts: list[dict[str, Any]],
    *, revision: str | None = None, allow_network: bool = False,
    max_new_tokens: int = 32, trials: int = 2, timeout_seconds: int = 600,
    device: str = "auto", output_dir: str | Path = "runs", include_output: bool = True,
    assessment_type: str = "llm_inference_smoke_test", sandbox: str = "required",
) -> dict[str, Any]:
    is_local, remote_allowed = _validate_model_source(model, revision, allow_network)
    if sandbox not in {"required", "off"}: raise ValueError("sandbox must be required or off")
    if sandbox == "required" and not is_local:
        raise ValueError("required Bubblewrap profile accepts local model directories only; download and audit the pinned snapshot first, or explicitly choose sandbox='off'")
    if not isinstance(prompts, list) or not 1 <= len(prompts) <= MAX_CASES:
        raise ValueError(f"prompts must contain 1..{MAX_CASES} cases")
    safe_prompts = []
    total_chars = 0
    seen_ids = set()
    for idx, item in enumerate(prompts):
        if not isinstance(item, dict) or not isinstance(item.get("prompt"), str) or not item["prompt"].strip():
            raise ValueError(f"case {idx + 1} must contain non-empty prompt text")
        prompt = item["prompt"]
        total_chars += len(prompt)
        if len(prompt) > MAX_PROMPT_CHARS:
            raise ValueError(f"case {idx + 1} exceeds {MAX_PROMPT_CHARS} characters")
        case_id = str(item.get("id") or f"case-{idx+1}")[:100]
        if case_id in seen_ids: raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        checks = item.get("checks", [])
        if not isinstance(checks, list) or len(checks) > 10:
            raise ValueError(f"case {case_id}: checks must be a list of at most 10 checks")
        clean_checks = []
        for check in checks:
            if not isinstance(check, dict) or check.get("type") not in {"contains", "equals", "valid_json"}:
                raise ValueError(f"case {case_id}: check type must be contains, equals, or valid_json")
            if check["type"] in {"contains", "equals"} and not isinstance(check.get("value"), str):
                raise ValueError(f"case {case_id}: {check['type']} requires a string value")
            clean_checks.append(check)
        safe_prompts.append({"id": case_id, "prompt": prompt, "checks": clean_checks})
    if total_chars > 100_000:
        raise ValueError("total prompt text exceeds 100,000 characters")
    if not (1 <= max_new_tokens <= MAX_NEW_TOKENS): raise ValueError(f"max_new_tokens must be in 1..{MAX_NEW_TOKENS}")
    if not (1 <= trials <= 3): raise ValueError("trials must be in 1..3")
    if not (10 <= timeout_seconds <= 1800): raise ValueError("timeout_seconds must be in 10..1800")
    if device not in {"auto", "cpu", "cuda"}: raise ValueError("device must be auto, cpu, or cuda")

    exp_id = "mbl-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
    out_dir = Path(output_dir).expanduser().resolve()
    out_path = out_dir / f"{exp_id}.json"
    sandbox_probe = None
    if sandbox == "required":
        model_audit = audit_model_directory(model, hash_files=False)
        escaping = [x for x in model_audit["findings"] if x.get("id") == "MBL-MODEL-SYMLINK-001"]
        if escaping:
            result = {"schema_version":SCHEMA_VERSION,"experiment_id":exp_id,"generated_at_utc":utc_now(),
                "evidence_class":"observed","assessment_type":assessment_type,"status":"SANDBOX_BLOCKED_MODEL_LAYOUT",
                "model_tested":False,"model_id":model,"reason":"Model directory contains broken or escaping symlinks; refusing to expose files outside the declared model tree.",
                "finding_count":len(escaping),"prompt_stored":False,
                "security_assessment":{"status":"NOT_ESTABLISHED","reason":"No model process was started."}}
            json_dump_atomic(out_path, result); result["report_path"]=str(out_path); return result
        sandbox_probe = probe_bwrap()
        if sandbox_probe.get("status") != "PRECHECK_PASS":
            result = {"schema_version":SCHEMA_VERSION,"experiment_id":exp_id,"generated_at_utc":utc_now(),
                "evidence_class":"observed","assessment_type":assessment_type,"status":"SANDBOX_UNAVAILABLE",
                "model_tested":False,"model_id":model,"sandbox_probe":sandbox_probe,"prompt_stored":False,
                "reason":"The required Bubblewrap preflight did not pass. No model was loaded.",
                "security_assessment":{"status":"NOT_ESTABLISHED","reason":"No model process was started."}}
            json_dump_atomic(out_path, result); result["report_path"]=str(out_path); return result
    args = [sys.executable, "-m", "mbl.cli", "_infer-worker", "--model", model,
            "--max-new-tokens", str(max_new_tokens), "--trials", str(trials), "--device", device,
            "--batch-json", "--sandbox-profile", sandbox,
            "--include-output" if include_output else "--redact-output"]
    args += ["--local-only"] if is_local else ["--revision", str(revision), "--allow-network"]
    source_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(source_root) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    expected_host_namespaces = (sandbox_probe or {}).get("host_namespace_ids")
    if sandbox == "required":
        args = build_bwrap_command(args, Path(model), source_root, sandbox_probe["executable"])
        # Prevent host credentials and unrelated user environment from being inherited by bwrap.
        env = {"PATH": str(Path(sandbox_probe["executable"]).parent), "LANG": "C.UTF-8"}
    started = time.monotonic()
    try:
        payload = {"prompts": safe_prompts, "sandbox_profile": sandbox, "host_namespace_ids": expected_host_namespaces}
        proc = subprocess.run(args, input=json.dumps(payload, ensure_ascii=False),
                              text=True, capture_output=True, timeout=timeout_seconds, env=env, check=False)
    except subprocess.TimeoutExpired:
        result = {"schema_version": SCHEMA_VERSION, "experiment_id": exp_id,
            "generated_at_utc": utc_now(), "evidence_class": "observed", "assessment_type": assessment_type,
            "status": "TIMEOUT", "model_tested": False, "model_id": model,
            "revision_requested": revision, "case_count": len(safe_prompts),
            "prompt_hashes": [{"id": x["id"], "sha256": sha256_text(x["prompt"])} for x in safe_prompts],
            "prompt_stored": False, "timeout_seconds": timeout_seconds,
            "wall_time_seconds": round(time.monotonic()-started,3),
            "security_assessment": {"status":"NOT_ESTABLISHED","reason":"A timeout is not evidence of isolation or confidentiality."}}
    else:
        try: worker = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.stdout.strip() else None
        except (json.JSONDecodeError, IndexError): worker = None
        if isinstance(worker, dict):
            result = worker
            result["experiment_id"] = exp_id
            result["assessment_type"] = assessment_type
            result["sandbox_requested"] = sandbox
            if sandbox_probe is not None: result["sandbox_probe"] = sandbox_probe
            result["parent_wall_time_seconds"] = round(time.monotonic()-started, 3)
            result["prompt_stored"] = False
            result["prompt_hashes"] = [{"id": x["id"], "sha256": sha256_text(x["prompt"])} for x in safe_prompts]
            result["worker_exit_code"] = proc.returncode
            if proc.returncode != 0 and result.get("status") == "PASS_SMOKE_ONLY": result["status"] = "INCONCLUSIVE"
        else:
            result = {"schema_version": SCHEMA_VERSION, "experiment_id": exp_id,
                "generated_at_utc": utc_now(), "evidence_class":"observed", "assessment_type":assessment_type,
                "status":"ERROR", "model_tested":False, "model_id":model,
                "revision_requested":revision, "parent_wall_time_seconds":round(time.monotonic()-started,3),
                "error_type":"WorkerProtocolError", "worker_exit_code":proc.returncode,
                "stderr_tail":proc.stderr[-2000:], "prompt_stored":False}
    result.setdefault("security_assessment", {"status":"NOT_ESTABLISHED","reason":"Inference results do not establish isolation or model-weight confidentiality."})
    json_dump_atomic(out_path, result)
    result["report_path"] = str(out_path)
    return result


def run_model(model: str, prompt: str, **kwargs: Any) -> dict[str, Any]:
    return run_prompts(model, [{"id": "smoke-1", "prompt": prompt}], **kwargs)


def run_benchmark_file(model: str, suite_path: str | Path, **kwargs: Any) -> dict[str, Any]:
    cases = []
    for line_no, line in enumerate(Path(suite_path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"): continue
        try: obj = json.loads(line)
        except json.JSONDecodeError as exc: raise ValueError(f"invalid JSONL on line {line_no}: {exc.msg}")
        cases.append(obj)
    return run_prompts(model, cases, assessment_type="llm_regression_benchmark", **kwargs)


def _apply_checks(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    out = []
    for check in checks:
        kind = check["type"]
        if kind == "contains": passed = check["value"] in text
        elif kind == "equals": passed = text.strip() == check["value"].strip()
        elif kind == "valid_json":
            try: json.loads(text); passed = True
            except json.JSONDecodeError: passed = False
        else: passed = False
        out.append({"type": kind, "passed": passed, "expected": check.get("value") if kind != "valid_json" else None})
    return {"checks": out, "check_count": len(out), "passed_count": sum(1 for x in out if x["passed"]),
            "status": "PASS" if all(x["passed"] for x in out) else "FAIL" if out else "NOT_CONFIGURED"}


def worker_main(args: Any) -> int:
    try:
        raw = sys.stdin.read(100_001)
        if len(raw) > 100_000: raise ValueError("stdin payload exceeds 100,000 characters")
        payload = json.loads(raw) if args.batch_json else {"prompts": [{"id": "smoke-1", "prompt": raw, "checks": []}]}
        prompts = payload.get("prompts") if isinstance(payload, dict) else None
        sandbox_profile = payload.get("sandbox_profile", "off") if isinstance(payload, dict) else "off"
        host_namespace_ids = payload.get("host_namespace_ids") if isinstance(payload, dict) else None
        if not isinstance(prompts, list) or not prompts: raise ValueError("stdin must contain a non-empty prompts list")
        for item in prompts:
            if not isinstance(item, dict) or not isinstance(item.get("prompt"), str) or not item["prompt"].strip(): raise ValueError("invalid prompt case")
            if len(item["prompt"]) > MAX_PROMPT_CHARS: raise ValueError("prompt case is too long")
        import torch
        import transformers
        from transformers import AutoModelForCausalLM, AutoTokenizer
        runtime_snapshot = runtime_doctor()
        if sandbox_profile == "required":
            isolation_report = verify_child_boundary(runtime_snapshot["process_controls"]["namespace_ids"],
                host_namespace_ids or {}, runtime_snapshot["process_controls"]["no_new_privs"].get("raw"))
            mount_readonly = False
            try:
                for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace").splitlines():
                    fields = line.split(" - ", 1)[0].split()
                    if len(fields) > 5 and fields[4] == "/model":
                        mount_readonly = "ro" in fields[5].split(",")
                        break
            except OSError:
                pass
            try: interfaces = [entry[1] for entry in socket.if_nameindex()]
            except OSError: interfaces = []
            dangerous_env = [key for key in ("HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY") if os.environ.get(key)]
            home_visible = Path("/home").exists()
            profile_checks = {"model_mount_read_only":mount_readonly, "network_interfaces":interfaces,
                "no_non_loopback_network_interface":all(name == "lo" for name in interfaces),
                "host_home_visible":home_visible, "sensitive_environment_keys_present":dangerous_env}
            isolation_report["additional_checks"] = profile_checks
            profile_checks["network_interfaces_observed"] = bool(interfaces)
            profile_valid = (isolation_report.get("status") == "PARTIAL_CONTROLS_OBSERVED" and mount_readonly
                and bool(interfaces) and profile_checks["no_non_loopback_network_interface"] and not home_visible and not dangerous_env)
            isolation_report["status"] = "PARTIAL_CONTROLS_OBSERVED" if profile_valid else "INCONCLUSIVE"
            if not profile_valid:
                failure = {"schema_version":SCHEMA_VERSION,"generated_at_utc":utc_now(),"evidence_class":"observed",
                    "status":"SANDBOX_VERIFY_FAILED","model_tested":False,"model_id":args.model,
                    "runtime_isolation_snapshot":runtime_snapshot,"isolation_profile_evidence":isolation_report,
                    "reason":"Pre-load sandbox verification failed; model artifacts were not loaded.",
                    "security_assessment":{"status":"NOT_ESTABLISHED","reason":"Sandbox pre-load checks were inconclusive or failed."}}
                print(json.dumps(failure,ensure_ascii=False,separators=(",",":"))); return 2
        else:
            isolation_report = {"profile":"none", "status":"NOT_REQUESTED", "claim_boundary":"Child-process supervision is not kernel-enforced isolation."}
        model_ref = str(Path(args.model).expanduser().resolve()) if args.local_only else args.model
        t_load = time.monotonic()
        tokenizer = AutoTokenizer.from_pretrained(model_ref, revision=None if args.local_only else args.revision,
            trust_remote_code=False, local_files_only=args.local_only, token=None)
        model = AutoModelForCausalLM.from_pretrained(model_ref, revision=None if args.local_only else args.revision,
            trust_remote_code=False, local_files_only=args.local_only, use_safetensors=True,
            low_cpu_mem_usage=True, torch_dtype="auto", token=None)
        device = "cuda" if args.device == "auto" and torch.cuda.is_available() else "cpu" if args.device == "auto" else args.device
        if device == "cuda" and not torch.cuda.is_available(): raise RuntimeError("CUDA requested but CUDA is unavailable")
        model.to(device); model.eval(); load_seconds = round(time.monotonic()-t_load,3)
        all_cases = []; aggregate_pass = 0; aggregate_checks = 0; repeatability_mismatches = 0
        for item in prompts:
            prompt = item["prompt"]
            rendered = tokenizer.apply_chat_template([{"role":"user","content":prompt}], tokenize=False, add_generation_prompt=True) if getattr(tokenizer,"chat_template",None) else prompt
            inputs = {k:v.to(device) for k,v in tokenizer(rendered, return_tensors="pt").items()}
            input_tokens = int(inputs["input_ids"].shape[-1]); trial_records=[]
            for trial in range(args.trials):
                started=time.monotonic()
                with torch.inference_mode():
                    generated=model.generate(**inputs,max_new_tokens=args.max_new_tokens,do_sample=False,num_beams=1,use_cache=True,
                        pad_token_id=tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id)
                new_ids=generated[0][inputs["input_ids"].shape[-1]:]; decoded=tokenizer.decode(new_ids,skip_special_tokens=True)
                trial_records.append({"trial":trial+1,"elapsed_seconds":round(time.monotonic()-started,4),
                    "generated_token_count":int(new_ids.shape[-1]),"output_sha256":sha256_text(decoded),
                    "output_text":decoded if args.include_output else None})
            stable=len({x["output_sha256"] for x in trial_records})==1
            if not stable: repeatability_mismatches += 1
            representative=trial_records[0].get("output_text")
            # If text redacted, use local text retained only in memory for check evaluation.
            if representative is None:
                text_for_check = tokenizer.decode(generated[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)
            else: text_for_check=representative
            checks=_apply_checks(text_for_check,item.get("checks",[]))
            aggregate_pass += checks["passed_count"]; aggregate_checks += checks["check_count"]
            all_cases.append({"id":str(item.get("id") or f"case-{len(all_cases)+1}"),"prompt_sha256":sha256_text(prompt),
                "input_token_count":input_tokens,"trial_count":len(trial_records),"repeatability":{"status":"MATCH" if stable else "MISMATCH","same_greedy_output_hash":stable},
                "checks":checks,"trials":trial_records})
        num_params=getattr(model,"num_parameters",None); param_count=int(num_params()) if callable(num_params) else None
        failures=sum(1 for x in all_cases for c in x["checks"]["checks"] if not c["passed"])
        result={"schema_version":SCHEMA_VERSION,"generated_at_utc":utc_now(),"evidence_class":"observed",
            "status":"PASS_SMOKE_ONLY","model_tested":True,"model_id":args.model,
            "revision_requested":args.revision,"revision_resolved":getattr(model.config,"_commit_hash",None),
            "local_only":args.local_only,"trust_remote_code":False,"use_safetensors":True,"device":device,
            "runtime":{"python":sys.version.split()[0],"torch":torch.__version__,"transformers":transformers.__version__},
            "model_metadata":{"model_type":getattr(model.config,"model_type",None),"architectures":getattr(model.config,"architectures",None),"parameter_count":param_count},
            "load_seconds":load_seconds,"max_new_tokens":args.max_new_tokens,"case_count":len(all_cases),"trial_count_per_case":args.trials,
            "benchmark_summary":{"checks":aggregate_checks,"passed":aggregate_pass,"failed":failures,"repeatability_mismatches":repeatability_mismatches,
                "status":"PASS" if failures==0 and repeatability_mismatches==0 else "FAIL" if failures or repeatability_mismatches else "NOT_CONFIGURED"},
            "runtime_isolation_snapshot":runtime_snapshot,
            "isolation_profile_evidence":isolation_report,
            "cases":all_cases,"claim_boundary":"Smoke/regression result only. Even when selected namespace differences are observed, this is not a full sandbox security proof or a weight-confidentiality result.",
            "security_assessment":{"status":"NOT_ESTABLISHED","reason":"Inference success, stable output, and task-level checks do not demonstrate an enforced process boundary or weight confidentiality."}}
        print(json.dumps(result,ensure_ascii=False,separators=(",",":"))); return 0
    except Exception as exc:
        result={"schema_version":SCHEMA_VERSION,"generated_at_utc":utc_now(),"evidence_class":"observed",
            "status":"NOT_RUN","model_tested":False,"model_id":args.model,"revision_requested":args.revision,
            "error_type":type(exc).__name__,"error":str(exc)[:1500],"prompt_stored":False,
            "security_assessment":{"status":"NOT_ESTABLISHED","reason":"Inference failed or did not run; no security conclusion is possible."}}
        print(json.dumps(result,ensure_ascii=False,separators=(",",":"))); return 2
