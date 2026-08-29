#!/usr/bin/env python3
"""Lint a proposed CTF shell command before execution.

This does not execute commands. It is an extra guardrail for agent-derived shell work.
"""

from __future__ import annotations

import argparse
import re


_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sensitive host credential path", re.compile(r"(?i)(?:~|/home/[^/]+)/(?:\.ssh|\.aws|\.config/gcloud|\.kube)(?:/|\b)|\bid_(?:rsa|ed25519|ecdsa)\b")),
    ("sensitive credential variable", re.compile(r"(?i)\b(?:GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|CTF_TOKEN)\b")),
    ("sensitive credential command", re.compile(r"(?i)\b(?:gh\s+auth\s+token|git\s+credential|security\s+find-(?:generic|internet)-password)\b")),
    ("cloud metadata endpoint", re.compile(r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)")),
    ("fetch-and-execute pipeline", re.compile(r"(?is)\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python(?:3)?|perl|ruby)\b")),
    ("destructive host command", re.compile(r"(?i)(?:\brm\s+-rf\s+/(?:\s|$)|\bmkfs(?:\.|\s)|\bshutdown\b|\breboot\b|:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;\s*: )")),
)

_ENV_PATTERN = re.compile(r"(?i)(?:\bprintenv\b|/proc/(?:self|\d+)/environ|\bcompgen\s+-e\b|\benv\s*\|)")
_NETWORK_PATTERN = re.compile(r"(?i)\b(?:curl|wget|nc|ncat|socat|ssh|scp|ftp)\b")


def assess_command(command: str, origin: str) -> tuple[bool, str]:
    if origin not in {"agent", "challenge"}:
        return False, "origin must be 'agent' or 'challenge'"
    if origin == "challenge":
        return False, "untrusted challenge content may not supply executable commands; re-derive the action independently"

    stripped = command.strip()
    if not stripped:
        return False, "empty command"

    if _ENV_PATTERN.search(stripped):
        if _NETWORK_PATTERN.search(stripped):
            return False, "environment access combined with network transfer is forbidden"
        return False, "environment enumeration is sensitive and forbidden during CTF solving"

    for reason, pattern in _SENSITIVE_PATTERNS:
        if pattern.search(stripped):
            if reason.startswith("sensitive"):
                return False, f"sensitive access forbidden: {reason}"
            return False, f"forbidden: {reason}"

    return True, "agent-derived CTF analysis command accepted by static guard"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", choices=("agent", "challenge"), required=True)
    parser.add_argument("command", help="Command text to lint; it will not be executed")
    args = parser.parse_args(argv)
    allowed, reason = assess_command(args.command, args.origin)
    print(("ALLOW: " if allowed else "DENY: ") + reason)
    return 0 if allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
