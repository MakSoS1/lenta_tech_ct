#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_ROOT="${CTF_WORK_ROOT:-$ROOT/.ctf-work}"
TASK_ID="${1:-}"
TARGET="${2:-}"

if [[ ! "$TASK_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "register-target: invalid task id" >&2
  exit 2
fi
TASK_DIR="$WORK_ROOT/$TASK_ID"
if [[ ! -d "$TASK_DIR" ]]; then
  echo "register-target: unknown task; run new_task.sh first" >&2
  exit 2
fi
if [[ -z "$TARGET" ]]; then
  echo "register-target: target is required" >&2
  exit 2
fi

HOST="$(python3 - "$TARGET" <<'PY'
import sys
import urllib.parse

raw = sys.argv[1].strip()
if not raw or any(ord(ch) < 32 for ch in raw):
    raise SystemExit("invalid target")
if "://" in raw:
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise SystemExit("only http/https URLs or raw host[:port] targets are accepted")
else:
    parsed = urllib.parse.urlsplit("//" + raw)
if parsed.username is not None or parsed.password is not None:
    raise SystemExit("embedded credentials are forbidden")
if not parsed.hostname:
    raise SystemExit("target has no hostname")
print(parsed.hostname.lower().rstrip("."))
PY
)"

TARGETS="$TASK_DIR/targets.txt"
touch "$TARGETS"
if ! grep -Fqx -- "$HOST" "$TARGETS"; then
  printf '%s\n' "$HOST" >> "$TARGETS"
fi
printf 'register-target: authorized host %s for task %s\n' "$HOST" "$TASK_ID"
