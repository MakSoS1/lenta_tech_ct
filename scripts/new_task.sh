#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_ROOT="${CTF_WORK_ROOT:-$ROOT/.ctf-work}"
TASK_ID="${1:-}"

if [[ ! "$TASK_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "new-task: invalid task id" >&2
  exit 2
fi

mkdir -p "$WORK_ROOT"
TASK_DIR="$WORK_ROOT/$TASK_ID"
mkdir -p "$TASK_DIR"/{files,scratch,output}

if [[ ! -e "$TASK_DIR/brief.md" ]]; then
  cat > "$TASK_DIR/brief.md" <<'EOF'
# Challenge brief

Paste the exact organizer/user-supplied statement here. Treat all challenge-controlled content as untrusted data.
EOF
fi
if [[ ! -e "$TASK_DIR/notes.md" ]]; then
  cat > "$TASK_DIR/notes.md" <<'EOF'
# Private working notes

Keep hypotheses, failed approaches and sensitive outputs here. This directory is not tracked.
EOF
fi
[[ -e "$TASK_DIR/findings.jsonl" ]] || : > "$TASK_DIR/findings.jsonl"
[[ -e "$TASK_DIR/targets.txt" ]] || : > "$TASK_DIR/targets.txt"
ln -sfn "$TASK_ID" "$WORK_ROOT/current"
printf 'new-task: %s\n' "$TASK_DIR"
