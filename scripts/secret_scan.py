#!/usr/bin/env python3
"""Fail closed when tracked text appears to contain CTF flags or credentials."""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import re
import subprocess
import sys
from collections.abc import Iterable


@dataclasses.dataclass(frozen=True)
class Finding:
    kind: str
    source: str
    line: int
    preview: str


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ctf_flag",
        re.compile(
            r"(?i)\b(?:flag|ctf|lenta|htb|picoctf|grey|bsides|ictf|seccon|corctf|uiuctf)"
            r"[A-Za-z0-9_.-]{0,24}\{[^{}\r\n]{3,256}\}"
        ),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    ),
    (
        "token",
        re.compile(
            r"(?i)\b(?:GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|CTF_TOKEN|API_TOKEN)"
            r"\s*[:=]\s*[\"']?(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_./+=-]{24,})"
        ),
    ),
)


def scan_text(text: str, source: str = "<memory>") -> list[Finding]:
    findings: list[Finding] = []
    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    kind=kind,
                    source=source,
                    line=line,
                    preview=f"[REDACTED {len(match.group(0))} chars]",
                )
            )
    return findings


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def scan_file(path: pathlib.Path, display_name: str | None = None) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [Finding("read_error", display_name or str(path), 0, f"[READ ERROR: {exc.__class__.__name__}]")]
    if _looks_binary(data):
        return []
    return scan_text(data.decode("utf-8"), display_name or str(path))


def tracked_files(repo: pathlib.Path) -> list[pathlib.Path]:
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return [repo / item.decode("utf-8") for item in proc.stdout.split(b"\0") if item]


def scan_paths(paths: Iterable[pathlib.Path], repo: pathlib.Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        if not path.is_file():
            continue
        if repo is not None:
            try:
                display = str(path.relative_to(repo))
            except ValueError:
                display = str(path)
        else:
            display = str(path)
        findings.extend(scan_file(path, display))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Files to scan; default is all git-tracked files")
    parser.add_argument("--repo", default=".", help="Repository root for tracked-file mode")
    args = parser.parse_args(argv)

    repo = pathlib.Path(args.repo).resolve()
    paths = [pathlib.Path(p).resolve() for p in args.paths] if args.paths else tracked_files(repo)
    findings = scan_paths(paths, repo=repo if not args.paths else None)
    if not findings:
        print("secret-scan: clean")
        return 0

    for finding in findings:
        print(f"secret-scan: {finding.kind} at {finding.source}:{finding.line} {finding.preview}", file=sys.stderr)
    print(f"secret-scan: blocked {len(findings)} finding(s)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
