#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE_URL="${1:?usage: $0 https://github.com/OWNER/REPO.git [tag] [archive.zip] [wheel.whl]}"
TAG="${2:-v0.6.0}"
ARCHIVE="${3:-$ROOT/../model-boundary-lab-v0.6.0.zip}"
WHEEL="${4:-$ROOT/../model-boundary-lab-0.6.0-py3-none-any.whl}"

command -v git >/dev/null || { echo 'git is required' >&2; exit 127; }
command -v gh >/dev/null || { echo 'GitHub CLI gh is required' >&2; exit 127; }
cd "$ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git init -b main
fi
if git remote get-url origin >/dev/null 2>&1; then
  CURRENT_REMOTE="$(git remote get-url origin)"
  if [[ "$CURRENT_REMOTE" != "$REMOTE_URL" ]]; then
    echo "Refusing to push: origin is $CURRENT_REMOTE, not the supplied $REMOTE_URL" >&2
    exit 2
  fi
else
  git remote add origin "$REMOTE_URL"
fi

git add -A
if ! git diff --cached --quiet; then
  git commit -m "Prepare ModelBoundary Lab ${TAG}"
fi
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Tag $TAG already exists; refusing to overwrite" >&2
  exit 2
fi
git push -u origin HEAD
git tag -a "$TAG" -m "ModelBoundary Lab ${TAG}"
git push origin "$TAG"

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "GitHub release $TAG already exists; repository tag was pushed, release was not replaced."
else
  ASSETS=()
  [[ ! -f "$ARCHIVE" ]] || ASSETS+=("$ARCHIVE")
  [[ ! -f "$WHEEL" ]] || ASSETS+=("$WHEEL")
  [[ ! -f "$ROOT/SHA256SUMS.txt" ]] || ASSETS+=("$ROOT/SHA256SUMS.txt")
  gh release create "$TAG" "${ASSETS[@]}" \
    --title "ModelBoundary Lab ${TAG}" \
    --notes "Research and local tooling prototype. See README.md and BUILD_STATUS.json for tested capabilities and limits. Real-model inference and OS sandbox enforcement must not be assumed unless separately tested."
fi
