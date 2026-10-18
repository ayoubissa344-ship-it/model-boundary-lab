"""CLI entry point for ModelBoundary Lab."""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.parse
from pathlib import Path

from . import __version__
from .core import audit_model_directory, audit_pid, json_dump_atomic, runtime_doctor, validate_evidence
from .inference import run_model, run_benchmark_file, worker_main
from .gguf_inference import run_gguf


def _write_result(data, out: str | None) -> None:
    encoded = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if out:
        target = Path(out).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded, encoding="utf-8")
        print(json.dumps({"status": data.get("status", "OK"), "report_path": str(target.resolve())}, ensure_ascii=False))
    else:
        print(encoded, end="")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mbl", description="ModelBoundary Lab: model-artifact audit and reproducible local inference tooling")
    p.add_argument("--version", action="version", version=f"ModelBoundary Lab {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("doctor", help="observe current process isolation signals")
    q.add_argument("--out")
    q = sub.add_parser("resolve-model", help="resolve public Hub model metadata to an immutable commit SHA (metadata only)")
    q.add_argument("model_id", help="public Hugging Face repo ID, e.g. org/model")
    q.add_argument("--allow-network", action="store_true", help="explicitly allow a read-only request to huggingface.co")
    q.add_argument("--out")
    q = sub.add_parser("audit-model", help="statically inspect a local model directory; never executes model code")
    q.add_argument("model_dir")
    q.add_argument("--no-hash", action="store_true", help="skip per-file SHA-256; faster for large models")
    q.add_argument("--max-files", type=int, default=200000)
    q.add_argument("--out")
    q = sub.add_parser("inspect-pid", help="read-only Linux /proc snapshot for a PID")
    q.add_argument("pid", type=int)
    q.add_argument("--out")
    q = sub.add_parser("run-model", help="run an optional Transformers inference smoke test")
    q.add_argument("model", help="local model directory by default; Hub ID requires --allow-network + pinned SHA")
    src = q.add_mutually_exclusive_group(required=True)
    src.add_argument("--prompt-file")
    src.add_argument("--prompt-stdin", action="store_true")
    q.add_argument("--revision", help="full immutable 40-64 digit git commit SHA for a Hub model")
    q.add_argument("--allow-network", action="store_true", help="explicitly allow downloading model/tokenizer from Hub")
    q.add_argument("--max-new-tokens", type=int, default=32)
    q.add_argument("--trials", type=int, default=2)
    q.add_argument("--timeout", type=int, default=600, help="wall-clock timeout in seconds (10..1800)")
    q.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    q.add_argument("--out-dir", default="runs")
    q.add_argument("--redact-output", action="store_true", help="store only output hashes, not generated text")
    q.add_argument("--sandbox", choices=["required", "off"], default="required", help="require the Bubblewrap local, no-network profile (default); off is an explicit unsandboxed opt-out")
    q = sub.add_parser("benchmark", help="run a pinned/local model against a JSONL regression suite")
    q.add_argument("model")
    q.add_argument("suite", help="JSONL file with id, prompt, and optional checks")
    q.add_argument("--revision", help="full immutable commit SHA for a Hub model")
    q.add_argument("--allow-network", action="store_true")
    q.add_argument("--max-new-tokens", type=int, default=48)
    q.add_argument("--trials", type=int, default=1)
    q.add_argument("--timeout", type=int, default=900)
    q.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    q.add_argument("--out-dir", default="runs")
    q.add_argument("--redact-output", action="store_true")
    q.add_argument("--sandbox", choices=["required", "off"], default="required")
    q = sub.add_parser("validate-jsonl", help="validate MBL evidence JSONL")
    q.add_argument("path")
    q.add_argument("--out")
    q = sub.add_parser("serve", help="start local web dashboard; loopback only by default")
    q.add_argument("--host", default="127.0.0.1", help="only loopback is allowed unless separately reviewed")
    q.add_argument("--port", type=int, default=8765)
    q.add_argument("--runs-dir", default="runs")
    q = sub.add_parser("_infer-worker", help=argparse.SUPPRESS)
    q.add_argument("--model", required=True)
    q.add_argument("--revision")
    q.add_argument("--allow-network", action="store_true")
    q.add_argument("--local-only", action="store_true")
    q.add_argument("--batch-json", action="store_true")
    q.add_argument("--sandbox-profile", choices=["required", "off"], default="off")
    q.add_argument("--max-new-tokens", type=int, default=32)
    q.add_argument("--trials", type=int, default=2)
    q.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    o = q.add_mutually_exclusive_group()
    o.add_argument("--include-output", action="store_true")
    o.add_argument("--redact-output", action="store_true")

    q = sub.add_parser(
        "run-gguf",
        help="run a local GGUF inference smoke test without claiming sandbox isolation",
    )
    q.add_argument("model", help="path to a local .gguf file")
    q.add_argument("--server", help="path to the llama-server executable")
    q.add_argument("--prompt-file", help="read prompt from a UTF-8 file")
    q.add_argument("--max-new-tokens", type=int, default=32)
    q.add_argument("--trials", type=int, default=1)
    q.add_argument("--timeout", type=int, default=180)
    q.add_argument("--out-dir", default="runs")
    q.add_argument(
        "--sandbox",
        choices=["off", "required"],
        default="off",
        help="required is rejected until GGUF has a verified Bubblewrap backend",
    )
    o = q.add_mutually_exclusive_group()
    o.add_argument("--include-output", action="store_true")
    o.add_argument("--redact-output", action="store_true")

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            result = runtime_doctor(); _write_result(result, args.out); return 0
        if args.command == "resolve-model":
            if not args.allow_network:
                raise ValueError("network access is disabled by default; pass --allow-network for metadata lookup")
            if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.model_id) or ".." in args.model_id:
                raise ValueError("model_id must look like org/model")
            url = "https://huggingface.co/api/models/" + urllib.parse.quote(args.model_id, safe="/")
            request = urllib.request.Request(url, headers={"User-Agent":"ModelBoundary-Lab/0.6.0", "Accept":"application/json"})
            with urllib.request.urlopen(request, timeout=15) as response:
                metadata = json.loads(response.read(2_000_000).decode("utf-8"))
            sha = metadata.get("sha")
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
                raise ValueError("Hub response did not contain a full immutable commit SHA")
            result = {"schema_version":"mbl-model-pin/1.0", "model_id":args.model_id, "revision":sha,
                "pipeline_tag":metadata.get("pipeline_tag"), "library_name":metadata.get("library_name"),
                "license":(metadata.get("cardData") or {}).get("license"), "evidence_class":"observed",
                "metadata_source":url, "warning":"Resolved commit metadata only; weights have not been downloaded or tested."}
            _write_result(result, args.out); return 0
        if args.command == "audit-model":
            result = audit_model_directory(args.model_dir, max_files=args.max_files, hash_files=not args.no_hash); _write_result(result, args.out); return 0
        if args.command == "inspect-pid":
            result = audit_pid(args.pid); _write_result(result, args.out); return 0
        if args.command == "run-model":
            prompt = Path(args.prompt_file).read_text(encoding="utf-8") if args.prompt_file else sys.stdin.read()
            result = run_model(args.model, prompt, revision=args.revision, allow_network=args.allow_network,
                max_new_tokens=args.max_new_tokens, trials=args.trials, timeout_seconds=args.timeout,
                device=args.device, output_dir=args.out_dir, include_output=not args.redact_output, sandbox=args.sandbox)
            summary = {k: result.get(k) for k in ("status", "model_tested", "model_id", "repeatability", "report_path", "error_type", "error") if k in result}
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return 0 if result.get("status") == "PASS_SMOKE_ONLY" else 2
        if args.command == "run-gguf":
            prompt = (
                Path(args.prompt_file).read_text(encoding="utf-8")
                if args.prompt_file else sys.stdin.read()
            )
            result = run_gguf(
                args.model,
                prompt,
                server=args.server,
                max_new_tokens=args.max_new_tokens,
                trials=args.trials,
                timeout_seconds=args.timeout,
                output_dir=args.out_dir,
                include_output=not args.redact_output,
                sandbox=args.sandbox,
            )
            summary = {
                k: result.get(k)
                for k in (
                    "status", "model_tested", "model_id", "backend",
                    "sandbox_status", "security_assessment",
                    "repeatability", "report_path", "error_type", "error",
                )
                if k in result
            }
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return 0 if result.get("status") == "PASS_SMOKE_ONLY" else 2

        if args.command == "benchmark":
            result = run_benchmark_file(args.model, args.suite, revision=args.revision, allow_network=args.allow_network,
                max_new_tokens=args.max_new_tokens, trials=args.trials, timeout_seconds=args.timeout,
                device=args.device, output_dir=args.out_dir, include_output=not args.redact_output, sandbox=args.sandbox)
            summary = {k: result.get(k) for k in ("status", "model_tested", "model_id", "benchmark_summary", "report_path", "error_type", "error") if k in result}
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            if result.get("status") != "PASS_SMOKE_ONLY": return 2
            return 0 if result.get("benchmark_summary", {}).get("status") in {"PASS", "NOT_CONFIGURED"} else 3
        if args.command == "validate-jsonl":
            rows = []; errors = []
            for n, line in enumerate(Path(args.path).read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip(): continue
                try: obj = json.loads(line)
                except json.JSONDecodeError as e:
                    errors.append({"line": n, "error": f"invalid JSON: {e.msg}"}); continue
                for error in validate_evidence(obj): errors.append({"line": n, "error": error})
                rows.append(obj)
            result = {"schema_version": "mbl-jsonl-validation/1.0", "status": "PASS" if not errors else "FAIL", "records": len(rows), "errors": errors}
            _write_result(result, args.out); return 0 if not errors else 2
        if args.command == "serve":
            if args.host not in {"127.0.0.1", "localhost", "::1"}:
                print("Refusing non-loopback bind: the dashboard has no authentication and is intended for local use only.", file=sys.stderr)
                return 2
            from .web import serve
            serve(args.host, args.port, Path(args.runs_dir))
            return 0
        if args.command == "_infer-worker":
            return worker_main(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "ERROR", "error_type": type(exc).__name__, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
