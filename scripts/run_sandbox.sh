#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_ROOT="${CTF_WORK_ROOT:-$ROOT/.ctf-work}"
TASK_ID="${1:-}"
[[ -n "$TASK_ID" ]] || { echo "usage: run_sandbox.sh <task-id> [--network] [--debug] [--image IMAGE] [command...]" >&2; exit 2; }
shift || true

if [[ ! "$TASK_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "sandbox: invalid task id" >&2
  exit 2
fi
TASK_DIR="$WORK_ROOT/$TASK_ID"
[[ -d "$TASK_DIR" ]] || { echo "sandbox: task workspace not found" >&2; exit 2; }

NETWORK="none"
DEBUG=0
IMAGE="lenta-ctf-fast"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --network) NETWORK="bridge"; shift ;;
    --debug) DEBUG=1; shift ;;
    --image) [[ $# -ge 2 ]] || { echo "sandbox: --image requires value" >&2; exit 2; }; IMAGE="$2"; shift 2 ;;
    --) shift; break ;;
    -*) echo "sandbox: unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done

CMD=("$@")
[[ ${#CMD[@]} -gt 0 ]] || CMD=(bash)
TTY=(-i)
[[ -t 0 && -t 1 ]] && TTY=(-it)

DOCKER_ARGS=(
  run --rm "${TTY[@]}"
  --name "lenta-ctf-${TASK_ID//[^A-Za-z0-9_.-]/-}-$$"
  --network "$NETWORK"
  --cap-drop=ALL
  --security-opt no-new-privileges
  --pids-limit "${CTF_DOCKER_PIDS:-512}"
  --memory "${CTF_DOCKER_MEMORY:-4g}"
  --cpus "${CTF_DOCKER_CPUS:-2}"
  --read-only
  --tmpfs "/tmp:rw,nosuid,nodev,size=1g"
  --tmpfs "/home/ctf:rw,nosuid,nodev,size=256m"
  --env HOME=/home/ctf
  --env LANG=C.UTF-8
  --mount "type=bind,src=$TASK_DIR,dst=/challenge,rw"
  --workdir /challenge
)
if [[ "$DEBUG" -eq 1 ]]; then
  DOCKER_ARGS+=(--cap-add=SYS_PTRACE --security-opt seccomp=unconfined)
fi

if [[ "$NETWORK" != "none" ]]; then
  echo "sandbox: network enabled; agent policy still restricts traffic to explicitly authorized CTF targets" >&2
fi
exec docker "${DOCKER_ARGS[@]}" "$IMAGE" "${CMD[@]}"
