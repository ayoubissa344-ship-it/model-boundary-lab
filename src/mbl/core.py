"""Dependency-free primitives for ModelBoundary Lab.

This module reports observable evidence; it deliberately avoids converting
missing signals into security claims.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "mbl-evidence/1.0"
SHA_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
WEIGHT_SUFFIXES = {".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".gguf", ".onnx", ".h5", ".msgpack"}
PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".token", ".secret"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def json_dump_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temp, path)


def _read_text(path: Path, max_bytes: int = 1024 * 1024) -> str | None:
    try:
        with path.open("rb") as fh:
            return fh.read(max_bytes).decode("utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def _status_fields(text: str | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if not text:
        return result
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def runtime_doctor() -> dict[str, Any]:
    """Collect safe, read-only local runtime telemetry."""
    proc_status = _status_fields(_read_text(Path("/proc/self/status")))
    namespace_map: dict[str, Any] = {}
    for name in ("user", "mnt", "net", "ipc", "uts", "pid", "cgroup", "time"):
        p = Path("/proc/self/ns") / name
        try:
            namespace_map[name] = {"status": "OBSERVED", "id": os.readlink(p)}
        except OSError as exc:
            namespace_map[name] = {"status": "INCONCLUSIVE", "reason": type(exc).__name__}
    try:
        limits = {}
        for line in Path("/proc/self/cgroup").read_text(encoding="utf-8", errors="replace").splitlines():
            limits.setdefault("membership_lines", []).append(line)
    except OSError:
        limits = {"membership_lines": None}
    tool_candidates = ("bwrap", "firejail", "setpriv", "prlimit", "unshare", "systemd-run", "nsjail", "docker", "podman")
    tools = {x: shutil.which(x) for x in tool_candidates}
    try:
        import importlib.metadata as im
        packages = {}
        for name in ("torch", "transformers", "safetensors", "accelerate", "huggingface-hub"):
            try:
                packages[name] = im.version(name)
            except im.PackageNotFoundError:
                packages[name] = None
    except Exception:
        packages = {}
    seccomp_raw = proc_status.get("Seccomp")
    nnp_raw = proc_status.get("NoNewPrivs")
    cap_raw = proc_status.get("CapEff")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "evidence_class": "observed",
        "runtime": {
            "os": platform.system(), "os_release": platform.release(),
            "architecture": platform.machine(), "python": platform.python_version(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
            "gid": os.getgid() if hasattr(os, "getgid") else None,
            "pid": os.getpid(), "platform": platform.platform(),
        },
        "process_controls": {
            "no_new_privs": {"raw": nnp_raw, "status": "OBSERVED" if nnp_raw is not None else "INCONCLUSIVE", "enabled": nnp_raw == "1"},
            "seccomp_mode": {"raw": seccomp_raw, "status": "OBSERVED" if seccomp_raw is not None else "INCONCLUSIVE", "interpretation": {"0": "disabled", "1": "strict", "2": "filter"}.get(seccomp_raw, "unknown_or_unavailable")},
            "effective_capabilities_hex": cap_raw,
            "namespace_ids": namespace_map,
            "cgroup": limits,
        },
        "available_tools": tools,
        "optional_packages": packages,
        "security_assessment": {
            "status": "NOT_ESTABLISHED",
            "reason": "Telemetry describes this process only. Namespace identity, Seccomp, and NoNewPrivs observations do not by themselves prove an effective or complete sandbox.",
        },
    }


def _tree_digest_record(path: Path, relative: str, include_content_hash: bool = True) -> dict[str, Any]:
    try:
        st = path.lstat()
        mode = stat.S_IMODE(st.st_mode)
        record: dict[str, Any] = {
            "path": relative,
            "kind": "symlink" if stat.S_ISLNK(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "directory" if stat.S_ISDIR(st.st_mode) else "other",
            "size_bytes": st.st_size,
            "mode_octal": format(mode, "04o"),
            "world_readable": bool(mode & stat.S_IROTH),
            "group_readable": bool(mode & stat.S_IRGRP),
            "world_writable": bool(mode & stat.S_IWOTH),
        }
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(path)
            record["symlink_target"] = target
            try:
                resolved = path.resolve(strict=True)
                record["symlink_escapes_model_dir"] = False  # filled by caller
                record["resolved_target"] = str(resolved)
            except OSError:
                record["symlink_broken"] = True
        elif stat.S_ISREG(st.st_mode) and include_content_hash:
            record["sha256"] = sha256_file(path)
        return record
    except OSError as exc:
        return {"path": relative, "kind": "unreadable", "error": type(exc).__name__}


def audit_model_directory(model_dir: str | Path, max_files: int = 200_000, hash_files: bool = True) -> dict[str, Any]:
    """Audit local model files without importing or executing model code."""
    root = Path(model_dir).expanduser().resolve(strict=False)
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Model path is not a directory: {root}")
    findings: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    total_bytes = 0
    count = 0
    config: dict[str, Any] = {}
    tokenizer_config: dict[str, Any] = {}
    config_path = root / "config.json"
    tconfig_path = root / "tokenizer_config.json"
    for path in (config_path, tconfig_path):
        if path.is_file() and not path.is_symlink():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if path.name == "config.json" and isinstance(data, dict):
                    config = data
                if path.name == "tokenizer_config.json" and isinstance(data, dict):
                    tokenizer_config = data
            except (OSError, json.JSONDecodeError) as exc:
                findings.append({"id": "MBL-MODEL-JSON-001", "severity": "HIGH", "status": "FINDING", "path": path.name, "detail": f"Invalid or unreadable JSON: {type(exc).__name__}"})
    # Do not follow symlink directories; inspect symlinks as links.
    for base, dirs, files in os.walk(root, followlinks=False):
        base_path = Path(base)
        symlink_dirs = [d for d in dirs if (base_path / d).is_symlink()]
        dirs[:] = sorted([d for d in dirs if not (base_path / d).is_symlink()])
        for name in sorted(dirs + symlink_dirs + files):
            path = base_path / name
            rel = path.relative_to(root).as_posix()
            count += 1
            if count > max_files:
                findings.append({"id": "MBL-MODEL-LIMIT-001", "severity": "HIGH", "status": "BLOCKED", "detail": f"File count exceeds limit {max_files}; audit truncated."})
                break
            record = _tree_digest_record(path, rel, include_content_hash=hash_files)
            if record["kind"] == "symlink":
                try:
                    record["symlink_escapes_model_dir"] = not Path(record["resolved_target"]).is_relative_to(root)
                except (KeyError, ValueError):
                    pass
                if record.get("symlink_escapes_model_dir") or record.get("symlink_broken"):
                    findings.append({"id": "MBL-MODEL-SYMLINK-001", "severity": "HIGH", "status": "FINDING", "path": rel, "detail": "Symlink resolves outside model directory or is broken."})
            if record.get("kind") == "file":
                total_bytes += int(record.get("size_bytes", 0))
                suffix = path.suffix.lower()
                if suffix in PICKLE_SUFFIXES:
                    findings.append({"id": "MBL-MODEL-PICKLE-001", "severity": "HIGH", "status": "FINDING", "path": rel, "detail": "Legacy pickle-capable weight/container extension; do not deserialize untrusted files. Prefer safetensors when supported."})
                if suffix in SENSITIVE_SUFFIXES:
                    findings.append({"id": "MBL-MODEL-SECRET-001", "severity": "CRITICAL", "status": "FINDING", "path": rel, "detail": "Potential private key/secret file appears inside model directory. Review and remove if unintended."})
                if suffix == ".py":
                    findings.append({"id": "MBL-MODEL-CODE-001", "severity": "MEDIUM", "status": "FINDING", "path": rel, "detail": "Python source exists in model repository. Static presence is not proof it will execute; keep remote code disabled unless reviewed."})
                if record.get("world_writable"):
                    findings.append({"id": "MBL-MODEL-PERM-001", "severity": "HIGH", "status": "FINDING", "path": rel, "detail": "File is world-writable."})
            records.append(record)
        if count > max_files:
            break
    auto_maps = config.get("auto_map") or tokenizer_config.get("auto_map")
    if auto_maps:
        findings.append({"id": "MBL-MODEL-AUTOMAP-001", "severity": "HIGH", "status": "FINDING", "path": "config.json/tokenizer_config.json", "detail": "auto_map declares custom AutoClass mappings. This tool does not execute them; review code and keep trust_remote_code=False by default."})
    if not any(x["kind"] == "file" and x["path"].endswith(".safetensors") for x in records):
        findings.append({"id": "MBL-MODEL-SAFEWEIGHTS-001", "severity": "MEDIUM", "status": "FINDING", "detail": "No .safetensors file detected. This is not necessarily invalid for every format, but safe tensor serialization could not be confirmed."})
    if not config:
        findings.append({"id": "MBL-MODEL-CONFIG-001", "severity": "MEDIUM", "status": "FINDING", "path": "config.json", "detail": "No valid config.json was found; this may be a non-Transformers model directory."})
    severities = {f["severity"] for f in findings if f["status"] == "FINDING"}
    risk = "CRITICAL" if "CRITICAL" in severities else "HIGH" if "HIGH" in severities else "MEDIUM" if "MEDIUM" in severities else "LOW"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "evidence_class": "observed",
        "assessment_type": "static_model_artifact_audit",
        "model_path": str(root),
        "model_metadata": {
            "model_type": config.get("model_type"), "architectures": config.get("architectures"),
            "tokenizer_class": tokenizer_config.get("tokenizer_class"),
            "declares_auto_map": bool(auto_maps),
        },
        "summary": {"file_count": len(records), "total_bytes": total_bytes, "finding_count": len(findings), "risk_label": risk},
        "files": records,
        "findings": findings,
        "limitations": [
            "Static inspection does not prove that artifacts are benign or free from supply-chain compromise.",
            "Hashes identify observed bytes; they do not authenticate publisher identity unless compared with a trusted manifest.",
            "File permissions do not isolate a model from a privileged host administrator or necessarily from processes sharing the same UID.",
            "No model code, pickle payload, custom AutoClass code, or inference runtime was executed by this audit.",
        ],
        "security_assessment": {"status": "NOT_ESTABLISHED", "reason": "Static artifact review is not a sandbox or a proof of model security."},
    }


def audit_pid(pid: int) -> dict[str, Any]:
    """Read-only snapshot of a Linux process visible through /proc."""
    if pid <= 0:
        raise ValueError("PID must be a positive integer")
    root = Path("/proc") / str(pid)
    if not root.is_dir():
        raise ValueError(f"PID {pid} is not visible under /proc")
    status = _status_fields(_read_text(root / "status"))
    namespaces: dict[str, Any] = {}
    for n in ("user", "mnt", "net", "ipc", "uts", "pid", "cgroup", "time"):
        try:
            namespaces[n] = {"status": "OBSERVED", "id": os.readlink(root / "ns" / n)}
        except OSError as exc:
            namespaces[n] = {"status": "INCONCLUSIVE", "reason": type(exc).__name__}
    cmdline_raw = _read_text(root / "cmdline", max_bytes=64 * 1024)
    cmdline = cmdline_raw.replace("\x00", " ").strip() if cmdline_raw is not None else None
    try:
        executable = os.readlink(root / "exe")
    except OSError:
        executable = None
    uid_values = status.get("Uid", "").split()
    gid_values = status.get("Gid", "").split()
    cgroup = _read_text(root / "cgroup")
    return {
        "schema_version": SCHEMA_VERSION, "generated_at_utc": utc_now(),
        "evidence_class": "observed", "assessment_type": "linux_process_snapshot",
        "pid": pid,
        "identity": {"uid_fields": uid_values, "gid_fields": gid_values, "name": status.get("Name"), "state": status.get("State"), "nspid": status.get("NSpid")},
        "executable": executable,
        "cmdline_sha256": sha256_text(cmdline) if cmdline is not None else None,
        "cmdline_stored": False,
        "controls": {
            "no_new_privs": status.get("NoNewPrivs"), "seccomp": status.get("Seccomp"),
            "seccomp_filters": status.get("Seccomp_filters"), "cap_eff": status.get("CapEff"),
            "cap_bnd": status.get("CapBnd"), "threads": status.get("Threads"),
        },
        "namespaces": namespaces,
        "cgroup_membership": cgroup.splitlines() if cgroup is not None else None,
        "security_assessment": {"status": "NOT_ESTABLISHED", "reason": "Process metadata is observational and does not prove effective isolation."},
    }


def validate_evidence(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["record must be a JSON object"]
    if record.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must equal {SCHEMA_VERSION}")
    if record.get("evidence_class") not in {"observed", "synthetic", "derived"}:
        errors.append("evidence_class must be observed, synthetic, or derived")
    assessment = record.get("security_assessment")
    if isinstance(assessment, dict) and assessment.get("status") == "PROVEN_SECURE":
        errors.append("PROVEN_SECURE is not an accepted status for this tool")
    return errors
