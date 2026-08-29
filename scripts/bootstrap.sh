#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME="$ROOT/.runtime/upstreams"
MODE="runtime"
VERIFY_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --verify-only) VERIFY_ONLY=1 ;;
    --all) MODE="all" ;;
    *) echo "bootstrap: unknown option $arg" >&2; exit 2 ;;
  esac
done

python3 "$ROOT/scripts/validate_upstreams.py"
if [[ "$VERIFY_ONLY" -eq 1 ]]; then
  exit 0
fi

mkdir -p "$RUNTIME"

clone_exact() {
  local name="$1" url="$2" sha="$3" expected_csv="$4"
  local dest="$RUNTIME/$name"
  if [[ ! -d "$dest/.git" ]]; then
    rm -rf "$dest"
    mkdir -p "$dest"
    git -C "$dest" init -q
    git -C "$dest" remote add origin "$url"
  else
    local existing
    existing="$(git -C "$dest" remote get-url origin)"
    [[ "$existing" == "$url" ]] || { echo "bootstrap: origin mismatch for $name" >&2; exit 3; }
  fi

  git -C "$dest" fetch -q --depth=1 origin "$sha"
  local fetched
  fetched="$(git -C "$dest" rev-parse FETCH_HEAD)"
  [[ "$fetched" == "$sha" ]] || { echo "bootstrap: fetched SHA mismatch for $name" >&2; exit 3; }
  git -C "$dest" -c advice.detachedHead=false checkout -q --detach --force "$sha"
  git -C "$dest" clean -ffdqx
  [[ "$(git -C "$dest" rev-parse HEAD)" == "$sha" ]] || { echo "bootstrap: checkout SHA mismatch for $name" >&2; exit 3; }

  IFS=',' read -r -a expected <<< "$expected_csv"
  for rel in "${expected[@]}"; do
    [[ -e "$dest/$rel" ]] || { echo "bootstrap: $name missing expected path $rel" >&2; exit 3; }
  done
  echo "bootstrap: pinned $name@$sha"
}

while IFS=$'\t' read -r name url sha role expected; do
  clone_exact "$name" "$url" "$sha" "$expected"
done < <(python3 "$ROOT/scripts/validate_upstreams.py" --emit "$MODE")

if [[ -d "$RUNTIME/ctf-skills/.git" ]]; then
  "$ROOT/scripts/link_skills.sh"
fi

echo "bootstrap: complete ($MODE)"
