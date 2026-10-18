"""Optional Bubblewrap confinement profile for local model execution.

The profile creates separate user/mount/PID/network/IPC/UTS namespaces, a small
read-only filesystem view, and an isolated temporary directory. It is a useful
reduction of exposure, not a complete defense against kernel/runtime bugs.
"""
from __future__ import annotations
import os, shutil, subprocess, sys
from pathlib import Path
from typing import Any

REQUIRED_FLAGS = ("--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts")


def _namespace_ids() -> dict[str, str | None]:
    result = {}
    for name in ("user", "mnt", "net", "ipc", "uts", "pid"):
        try: result[name] = os.readlink(f"/proc/self/ns/{name}")
        except OSError: result[name] = None
    return result


def probe_bwrap(timeout: int = 5) -> dict[str, Any]:
    exe = shutil.which("bwrap")
    if not exe:
        return {"status":"NOT_SUPPORTED", "available":False, "executable":None,
                "reason":"bubblewrap (bwrap) is not installed or not on PATH; required-mode inference will not start."}
    args = [exe, "--die-with-parent", "--new-session", *REQUIRED_FLAGS, "--cap-drop", "ALL"]
    # Mount only runtime system directories needed to launch a simple binary.
    if Path("/usr").is_dir(): args += ["--ro-bind", "/usr", "/usr"]
    for path in ("/lib", "/lib64"):
        p = Path(path)
        if p.exists() and not p.is_symlink() and p.is_dir(): args += ["--ro-bind", path, path]
        elif p.is_symlink():
            target = os.readlink(path)
            args += ["--symlink", target, path]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--", "/usr/bin/true"]
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout,
                                env={"PATH":"/usr/bin:/bin", "LANG":"C.UTF-8"}, check=False)
    except subprocess.TimeoutExpired:
        return {"status":"INCONCLUSIVE", "available":True, "executable":exe, "reason":"bwrap preflight timed out"}
    except OSError as exc:
        return {"status":"NOT_SUPPORTED", "available":True, "executable":exe, "reason":f"could not execute bwrap: {type(exc).__name__}"}
    if result.returncode != 0:
        return {"status":"NOT_SUPPORTED", "available":True, "executable":exe,
                "reason":"bwrap namespace preflight failed; user namespaces or a required option may be unavailable",
                "exit_code":result.returncode, "stderr_tail":result.stderr[-1000:]}
    return {"status":"PRECHECK_PASS", "available":True, "executable":exe,
            "profile":"local-model-readonly-network-isolated-v1", "preflight_exit_code":0,
            "host_namespace_ids":_namespace_ids()}


def build_bwrap_command(worker_args: list[str], model_path: Path, source_root: Path, bwrap_exe: str) -> list[str]:
    model = model_path.resolve(strict=True)
    source = source_root.resolve(strict=True)
    if not model.is_dir() or not source.is_dir(): raise ValueError("sandbox requires a local model directory and source package directory")
    args = [bwrap_exe, "--die-with-parent", "--new-session", *REQUIRED_FLAGS, "--cap-drop", "ALL"]
    # Expose the OS runtime read-only, not the host home, credentials, or general data directories.
    if Path("/usr").is_dir(): args += ["--ro-bind", "/usr", "/usr"]
    for path in ("/lib", "/lib64"):
        p = Path(path)
        if p.exists() and not p.is_symlink() and p.is_dir(): args += ["--ro-bind", path, path]
        elif p.is_symlink(): args += ["--symlink", os.readlink(path), path]
    # Bind the Python prefix only when outside /usr; it contains the active interpreter and dependencies.
    prefix = Path(sys.prefix).resolve()
    usr = Path("/usr").resolve()
    try: prefix_inside_usr = prefix == usr or prefix.is_relative_to(usr)
    except ValueError: prefix_inside_usr = False
    if not prefix_inside_usr:
        # Ensure parents exist in the new root before binding the prefix itself.
        parents = list(reversed(prefix.parents))
        for parent in parents:
            if str(parent) == "/": continue
            args += ["--dir", str(parent)]
        args += ["--ro-bind", str(prefix), str(prefix)]
    # User workspace and model are each mounted to dedicated paths; home directories remain hidden.
    args += ["--dir", "/workspace", "--ro-bind", str(source), "/workspace/src"]
    args += ["--ro-bind", str(model), "/model"]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", "/tmp",
             "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
             "--setenv", "PYTHONPATH", "/workspace/src", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
             "--setenv", "HF_HUB_OFFLINE", "1", "--setenv", "TRANSFORMERS_OFFLINE", "1",
             "--setenv", "HF_HUB_DISABLE_TELEMETRY", "1", "--setenv", "TOKENIZERS_PARALLELISM", "false",
             "--setenv", "OMP_NUM_THREADS", "2"]
    modified = list(worker_args)
    try:
        index = modified.index("--model")
        modified[index + 1] = "/model"
    except (ValueError, IndexError):
        raise ValueError("worker command must include a --model argument")
    # Sandbox has no network, so enforce local-only regardless of caller input.
    if "--allow-network" in modified: modified.remove("--allow-network")
    if "--local-only" not in modified: modified.append("--local-only")
    if "--revision" in modified:
        idx = modified.index("--revision")
        del modified[idx:idx+2]
    if modified[:3] == [sys.executable, "-m", "mbl.cli"]:
        worker = modified[3:]
    else:
        worker = modified
    bootstrap = (
        "import ctypes,os,sys; "
        "libc=ctypes.CDLL(None,use_errno=True); "
        "rc=libc.prctl(38,1,0,0,0); "
        "rc==0 or (_ for _ in ()).throw(OSError(ctypes.get_errno(),'PR_SET_NO_NEW_PRIVS failed')); "
        "os.execv(sys.argv[1],sys.argv[1:])"
    )
    # -I -S suppress user site customization before PR_SET_NO_NEW_PRIVS is applied.
    args += ["--", sys.executable, "-I", "-S", "-c", bootstrap, sys.executable, "-m", "mbl.cli", *worker]
    return args


def verify_child_boundary(child_namespace_ids: dict[str, Any], host_namespace_ids: dict[str, str | None], no_new_privs: Any) -> dict[str, Any]:
    required = ("user", "mnt", "net", "ipc", "uts", "pid")
    comparisons = {}
    for name in required:
        child = child_namespace_ids.get(name, {}).get("id") if isinstance(child_namespace_ids.get(name), dict) else None
        host = host_namespace_ids.get(name)
        comparisons[name] = {"host":host, "child":child, "different":bool(host and child and host != child),
                             "status":"OBSERVED" if host and child else "INCONCLUSIVE"}
    changed = [k for k,v in comparisons.items() if v["different"]]
    all_changed = all(comparisons[k]["different"] for k in required)
    nnp_ok = str(no_new_privs) == "1"
    return {"profile":"local-model-readonly-network-isolated-v1",
            "status":"PARTIAL_CONTROLS_OBSERVED" if all_changed and nnp_ok else "INCONCLUSIVE",
            "changed_namespace_count":len(changed), "required_namespace_count":len(required),
            "no_new_privs_enabled":nnp_ok, "namespace_comparison":comparisons,
            "claim_boundary":"This verifies selected namespace identifiers and NoNewPrivs only. It is not proof against kernel vulnerabilities, all filesystem escape paths, resource exhaustion, or other host threats."}
