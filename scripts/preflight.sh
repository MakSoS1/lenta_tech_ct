#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/validate_upstreams.py
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/*.py tests/*.py

for script in scripts/*.sh; do
  bash -n "$script"
done
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck scripts/*.sh
else
  echo "preflight: shellcheck not installed; bash -n completed"
fi

if git ls-files | grep -Eq '^(\.ctf-work|\.runtime|\.codex/skills|\.claude/skills)/'; then
  echo "preflight: private/runtime path is tracked" >&2
  exit 1
fi

python3 scripts/secret_scan.py --repo "$ROOT"
echo "preflight: all checks passed"
