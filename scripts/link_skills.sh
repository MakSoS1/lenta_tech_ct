#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/.runtime/upstreams/ctf-skills"
if [[ ! -d "$SOURCE/.git" ]]; then
  echo "link-skills: ctf-skills is not bootstrapped" >&2
  exit 2
fi

SKILLS=(
  solve-challenge
  ctf-web
  ctf-pwn
  ctf-crypto
  ctf-reverse
  ctf-forensics
  ctf-osint
  ctf-malware
  ctf-misc
  ctf-ai-ml
  ctf-writeup
)

for skill in "${SKILLS[@]}"; do
  [[ -f "$SOURCE/$skill/SKILL.md" ]] || { echo "link-skills: missing $skill/SKILL.md" >&2; exit 2; }
done

for provider in .codex .claude; do
  dest="$ROOT/$provider/skills"
  mkdir -p "$dest"
  for skill in "${SKILLS[@]}"; do
    rm -rf "${dest:?}/${skill:?}"
    ln -s "../../.runtime/upstreams/ctf-skills/$skill" "$dest/$skill"
  done
done

echo "link-skills: linked ${#SKILLS[@]} skills for Codex and Claude"
