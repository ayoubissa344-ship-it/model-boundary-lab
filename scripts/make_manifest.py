#!/usr/bin/env python3
"""Create a SHA-256 manifest for files not ignored by Git."""
from pathlib import Path
import hashlib
import subprocess

root = Path(__file__).resolve().parents[1]
out = root / "SHA256SUMS.txt"

skip_dirs = {
    ".git", ".venv", "__pycache__", ".pytest_cache",
    ".ruff_cache", ".mypy_cache", "node_modules",
    "target", "build", "dist", "runs", "htmlcov",
}
skip_suffixes = {
    ".pyc", ".pyo", ".whl", ".gguf", ".safetensors",
    ".pt", ".pth", ".onnx",
}

rows = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or path == out:
        continue

    rel = path.relative_to(root)
    if any(part in skip_dirs or part.endswith(".egg-info")
           for part in rel.parts):
        continue
    if path.suffix.lower() in skip_suffixes:
        continue
    if path.name.startswith("pytorch_model") and path.suffix.lower() == ".bin":
        continue
    if path.name in {"main.aux", "main.out", "main.log"}:
        continue

    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", rel.as_posix()],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if ignored.returncode == 0:
        continue
    if ignored.returncode != 1:
        raise RuntimeError(f"git check-ignore failed for {rel}")

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows.append(f"{digest}  {rel.as_posix()}")

out.write_text("\n".join(rows) + "\n", encoding="utf-8")
print(f"wrote {len(rows)} hashes to {out}")
