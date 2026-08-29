#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "install-hooks: repository checkout required" >&2
  exit 2
fi

chmod +x .githooks/pre-commit
git config --local core.hooksPath .githooks
echo "install-hooks: repository-local pre-commit protection enabled"
