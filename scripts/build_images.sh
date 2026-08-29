#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-fast}"
FAST_IMAGE="${CTF_FAST_IMAGE:-lenta-ctf-fast}"
VERIA_IMAGE="${CTF_VERIA_IMAGE:-ctf-sandbox}"

build_fast() {
  docker build -f "$ROOT/docker/Dockerfile.fast" -t "$FAST_IMAGE" "$ROOT"
  docker run --rm --network none "$FAST_IMAGE" bash -lc '
    set -e
    command -v python3
    command -v gdb
    command -v file
    command -v readelf
    command -v objdump
    command -v checksec
    command -v tshark
    command -v nmap
    python3 - <<"PY"
import Crypto
import pwn
import scapy.all
import z3
import volatility3
print("fast-toolbox: python imports OK")
PY
  '
}

build_veria() {
  "$ROOT/scripts/bootstrap.sh"
  local veria="$ROOT/.runtime/upstreams/ctf-agent"
  local dockerfile="$ROOT/.runtime/upstreams/ctf-agent/sandbox/Dockerfile.sandbox"
  [[ -f "$dockerfile" ]] || { echo "build-images: pinned Veria sandbox missing" >&2; exit 2; }
  docker build -f "$dockerfile" -t "$VERIA_IMAGE" "$veria"
}

case "$MODE" in
  fast) build_fast ;;
  veria) build_veria ;;
  all) build_fast; build_veria ;;
  *) echo "usage: build_images.sh [fast|veria|all]" >&2; exit 2 ;;
esac
