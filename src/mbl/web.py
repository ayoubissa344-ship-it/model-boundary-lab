"""Small dependency-free local dashboard with strict loopback defaults."""
from __future__ import annotations
import json
import mimetypes
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .core import audit_model_directory, audit_pid, json_dump_atomic, runtime_doctor
from .inference import run_model

MAX_REQUEST_BYTES = 64 * 1024


def _read_json(handler: BaseHTTPRequestHandler) -> dict:
    ctype = handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if ctype != "application/json":
        raise ValueError("Content-Type must be application/json")
    try:
        size = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        raise ValueError("invalid Content-Length")
    if size < 2 or size > MAX_REQUEST_BYTES:
        raise ValueError(f"request body size must be 2..{MAX_REQUEST_BYTES} bytes")
    obj = json.loads(handler.rfile.read(size).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("request JSON must be an object")
    return obj


def serve(host: str, port: int, runs_dir: Path) -> None:
    runs_dir = runs_dir.expanduser().resolve()
    runs_dir.mkdir(parents=True, exist_ok=True)
    ui_file = Path(__file__).resolve().parent / "static" / "index.html"
    if not ui_file.is_file(): ui_file = Path(__file__).resolve().parents[2] / "ui" / "index.html"

    class Handler(BaseHTTPRequestHandler):
        server_version = "ModelBoundaryLab/0.6"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Do not log request bodies/prompts; only method, path and status.
            super().log_message(fmt, *args)

        def _json(self, status: int, data: dict) -> None:
            raw = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(raw)

        def _host_ok(self) -> bool:
            host_header = self.headers.get("Host", "").lower()
            return host_header in {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or origin in {f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}"}

        def do_GET(self):
            if not self._host_ok():
                self._json(403, {"error": "Invalid Host header"}); return
            route = urlparse(self.path).path
            if route in {"/", "/index.html"}:
                try: raw = ui_file.read_bytes()
                except OSError:
                    self._json(500, {"error": "Dashboard asset missing. Reinstall package from source or launch from release directory."}); return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
                self.end_headers(); self.wfile.write(raw); return
            if route == "/api/health":
                self._json(200, {"status": "ok", "version": "0.6.0", "runs_dir": str(runs_dir)}); return
            if route == "/api/doctor":
                self._json(200, runtime_doctor()); return
            if route == "/api/runs":
                files = sorted(runs_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)[:30]
                records = []
                for file in files:
                    try:
                        obj = json.loads(file.read_text(encoding="utf-8"))
                        records.append({"file": file.name, "mtime": int(file.stat().st_mtime), "status": obj.get("status", "UNKNOWN"), "assessment_type": obj.get("assessment_type"), "model_id": obj.get("model_id")})
                    except (OSError, json.JSONDecodeError):
                        continue
                self._json(200, {"records": records}); return
            self._json(404, {"error": "Not found"})

        def do_POST(self):
            if not self._host_ok() or not self._origin_ok():
                self._json(403, {"error": "Host or Origin rejected; dashboard is loopback-only"}); return
            route = urlparse(self.path).path
            try:
                data = _read_json(self)
                if route == "/api/audit-model":
                    model_path = data.get("model_path")
                    if not isinstance(model_path, str) or not model_path.strip() or len(model_path) > 4096:
                        raise ValueError("model_path must be a non-empty path")
                    report = audit_model_directory(model_path, hash_files=bool(data.get("hash_files", True)))
                    name = f"artifact-audit-{int(time.time())}.json"
                    json_dump_atomic(runs_dir / name, report)
                    report["report_path"] = str(runs_dir / name)
                    self._json(200, report); return
                if route == "/api/inspect-pid":
                    pid = data.get("pid")
                    if isinstance(pid, bool) or not isinstance(pid, int): raise ValueError("pid must be an integer")
                    report = audit_pid(pid)
                    name = f"process-audit-{pid}-{int(time.time())}.json"
                    json_dump_atomic(runs_dir / name, report)
                    report["report_path"] = str(runs_dir / name)
                    self._json(200, report); return
                if route == "/api/run-model":
                    model = data.get("model")
                    prompt = data.get("prompt")
                    if not isinstance(model, str) or not isinstance(prompt, str): raise ValueError("model and prompt must be strings")
                    remote = bool(data.get("allow_network", False))
                    report = run_model(
                        model, prompt,
                        revision=data.get("revision") if isinstance(data.get("revision"), str) else None,
                        allow_network=remote,
                        max_new_tokens=int(data.get("max_new_tokens", 32)),
                        trials=int(data.get("trials", 2)),
                        timeout_seconds=int(data.get("timeout_seconds", 600)),
                        device=str(data.get("device", "auto")), output_dir=runs_dir,
                        include_output=bool(data.get("include_output", True)),
                        sandbox=str(data.get("sandbox", "required")),
                    )
                    self._json(200 if report.get("status") == "PASS_SMOKE_ONLY" else 422, report); return
                self._json(404, {"error": "Not found"})
            except (ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
                self._json(400, {"status": "ERROR", "error_type": type(exc).__name__, "error": str(exc)[:1000]})
            except Exception as exc:
                self._json(500, {"status": "ERROR", "error_type": type(exc).__name__, "error": str(exc)[:1000]})

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"ModelBoundary Lab dashboard: http://{host}:{port}")
    print(f"Run reports directory: {runs_dir}")
    print("Security note: loopback-only dashboard; do not expose it to a LAN or public interface.")
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\nStopping ModelBoundary Lab dashboard.")
    finally:
        server.server_close()
