"""Explicit local GGUF smoke testing through llama-server.

This backend is NOT sandboxed. It binds to loopback, disables the web UI,
uses a random API key, supervises the child process, and never stores prompts.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .core import SCHEMA_VERSION, json_dump_atomic, sha256_text, utc_now

MAX_PROMPT_CHARS = 20_000
MAX_NEW_TOKENS = 128


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request_json(url: str, payload: dict[str, Any] | None = None,
                  api_key: str = "", timeout: float = 2.0) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read(2_000_000).decode("utf-8"))
    if not isinstance(result, dict):
        raise ValueError("llama-server returned a non-object JSON response")
    return result


def run_gguf(
    model: str,
    prompt: str,
    *,
    server: str | None = None,
    max_new_tokens: int = 32,
    trials: int = 1,
    timeout_seconds: int = 180,
    output_dir: str | Path = "runs",
    include_output: bool = True,
    sandbox: str = "off",
) -> dict[str, Any]:
    """Run a bounded local GGUF smoke test; this is not a security assessment."""
    started = time.monotonic()
    model_path = Path(model).expanduser()

    if sandbox != "off":
        raise ValueError(
            "GGUF backend currently supports only --sandbox off; "
            "Bubblewrap integration is not implemented for this backend"
        )
    if not model_path.is_file() or model_path.suffix.lower() != ".gguf":
        raise ValueError("model must be an existing local .gguf file")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be non-empty text")
    if len(prompt) > MAX_PROMPT_CHARS:
        raise ValueError(f"prompt exceeds {MAX_PROMPT_CHARS} characters")
    if not 1 <= max_new_tokens <= MAX_NEW_TOKENS:
        raise ValueError(f"max_new_tokens must be in 1..{MAX_NEW_TOKENS}")
    if not 1 <= trials <= 3:
        raise ValueError("trials must be in 1..3")
    if not 10 <= timeout_seconds <= 1800:
        raise ValueError("timeout_seconds must be in 10..1800")

    executable = server or shutil.which("llama-server")
    if not executable:
        raise ValueError(
            "llama-server was not found; pass its path using --server"
        )
    executable_path = Path(executable).expanduser()
    if not executable_path.is_file() or not os.access(executable_path, os.X_OK):
        raise ValueError("server path must point to an executable file")

    model_path = model_path.resolve()
    out_dir = Path(output_dir).expanduser().resolve()
    exp_id = "mbl-gguf-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) \
        + "-" + secrets.token_hex(4)
    out_path = out_dir / f"{exp_id}.json"
    port = _free_loopback_port()
    api_key = secrets.token_urlsafe(32)

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": exp_id,
        "generated_at_utc": utc_now(),
        "evidence_class": "observed",
        "assessment_type": "gguf_inference_smoke_test",
        "backend": "llama-server",
        "model_id": str(model_path),
        "model_format": "GGUF",
        "model_tested": False,
        "sandbox_requested": "off",
        "sandbox_status": "NOT_REQUESTED",
        "prompt_stored": False,
        "prompt_sha256": sha256_text(prompt),
        "security_assessment": {
            "status": "NOT_ESTABLISHED",
            "reason": (
                "GGUF inference runs without Bubblewrap. Loopback binding "
                "and child-process supervision are not kernel isolation."
            ),
        },
    }

    proc: subprocess.Popen[str] | None = None
    try:
        command = [
            str(executable_path.resolve()),
            "--model", str(model_path),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--ctx-size", "512",
            "--predict", str(max_new_tokens),
            "--threads", "2",
            "--threads-batch", "2",
            "--n-gpu-layers", "0",
            "--no-webui",
            "--api-key", api_key,
        ]
        # Do not capture unlimited server logs in memory.
        log_path = out_dir / f"{exp_id}.server.log"
        out_dir.mkdir(parents=True, exist_ok=True)
        with log_path.open("w", encoding="utf-8") as log:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                close_fds=True,
                start_new_session=True,
                env={
                    "PATH": os.path.dirname(str(executable_path.resolve())),
                    "LANG": "C.UTF-8",
                    "HOME": str(Path.home()),
                },
            )

        base_url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + min(timeout_seconds, 120)
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"llama-server exited during startup with code {proc.returncode}"
                )
            try:
                _request_json(base_url + "/health", api_key=api_key, timeout=1.0)
                break
            except (OSError, ValueError, urllib.error.URLError):
                time.sleep(0.25)
        else:
            raise TimeoutError("llama-server did not become ready before startup deadline")

        trials_out = []
        for index in range(trials):
            remaining = timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("inference exceeded the wall-clock timeout")
            trial_start = time.monotonic()
            response = _request_json(
                base_url + "/completion",
                payload={
                    "prompt": prompt,
                    "n_predict": max_new_tokens,
                    "temperature": 0.0,
                    "cache_prompt": False,
                    "stream": False,
                },
                api_key=api_key,
                timeout=max(1.0, remaining),
            )
            generated = response.get("content")
            if not isinstance(generated, str):
                raise ValueError("llama-server response did not contain text content")
            trials_out.append({
                "trial": index + 1,
                "elapsed_seconds": round(time.monotonic() - trial_start, 4),
                "generated_token_count": response.get("tokens_predicted"),
                "output_sha256": sha256_text(generated),
                "output_text": generated if include_output else None,
                "stop_type": response.get("stop_type"),
            })

        stable = len({item["output_sha256"] for item in trials_out}) == 1
        result.update({
            "status": "PASS_SMOKE_ONLY",
            "model_tested": True,
            "local_only": True,
            "server_bind": "127.0.0.1",
            "web_ui_disabled": True,
            "max_new_tokens": max_new_tokens,
            "trial_count": trials,
            "repeatability": {
                "status": "MATCH" if stable else "MISMATCH",
                "same_greedy_output_hash": stable,
            },
            "trials": trials_out,
            "runtime": {
                "server_executable": str(executable_path.resolve()),
            },
        })
        if not stable:
            result["status"] = "INCONCLUSIVE"
    except (OSError, ValueError, RuntimeError, TimeoutError,
            urllib.error.URLError, json.JSONDecodeError) as exc:
        result.update({
            "status": "ERROR",
            "model_tested": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:1000],
        })
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    result["cleanup_warning"] = "server process did not exit after kill"
        result["wall_time_seconds"] = round(time.monotonic() - started, 3)
        json_dump_atomic(out_path, result)

    result["report_path"] = str(out_path)
    return result
