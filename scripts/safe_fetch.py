#!/usr/bin/env python3
"""Fetch an explicitly allowlisted HTTP(S) CTF target into ignored task storage."""

from __future__ import annotations

import argparse
import pathlib
import urllib.error
import urllib.parse
import urllib.request


def _normalize_hosts(hosts: set[str]) -> set[str]:
    return {host.strip().lower().rstrip(".") for host in hosts if host.strip()}


def validate_url(url: str, allowed_hosts: set[str]) -> urllib.parse.ParseResult:
    if any(ord(ch) < 32 for ch in url):
        raise ValueError("control characters are not allowed in URL")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("embedded URL credentials are forbidden")
    if not parsed.hostname:
        raise ValueError("URL must contain a hostname")
    host = parsed.hostname.lower().rstrip(".")
    if host not in _normalize_hosts(allowed_hosts):
        raise ValueError(f"host {host!r} is not in the explicit target allowlist")
    return parsed


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        absolute = urllib.parse.urljoin(req.full_url, newurl)
        validate_url(absolute, self.allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, absolute)


def _repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _task_dir(task_id: str) -> pathlib.Path:
    if not task_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in task_id):
        raise ValueError("invalid task id")
    root = (_repo_root() / ".ctf-work" / task_id).resolve()
    expected_parent = (_repo_root() / ".ctf-work").resolve()
    if root.parent != expected_parent:
        raise ValueError("task path escapes .ctf-work")
    return root


def _read_allowlist(task_dir: pathlib.Path) -> set[str]:
    path = task_dir / "targets.txt"
    if not path.is_file():
        raise ValueError("target allowlist is missing; use scripts/register_target.sh first")
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")}


def fetch_to_file(task_id: str, url: str, relative_output: str, timeout: float = 15.0, max_bytes: int = 8 * 1024 * 1024) -> tuple[int, int, str]:
    task_dir = _task_dir(task_id)
    allowlist = _read_allowlist(task_dir)
    validate_url(url, allowlist)

    output = (task_dir / relative_output).resolve()
    if task_dir not in output.parents:
        raise ValueError("output must stay inside the task workspace")
    output.parent.mkdir(parents=True, exist_ok=True)

    opener = urllib.request.build_opener(_AllowlistedRedirectHandler(allowlist))
    request = urllib.request.Request(url, headers={"User-Agent": "lenta-ctf-safe-fetch/1"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError("response exceeds maximum allowed size")
            output.write_bytes(body)
            return int(response.status), len(body), response.headers.get_content_type()
    except urllib.error.HTTPError as exc:
        body = exc.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError("response exceeds maximum allowed size") from exc
        output.write_bytes(body)
        return int(exc.code), len(body), exc.headers.get_content_type()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", required=True, help="Relative path within .ctf-work/<task>/")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)
    args = parser.parse_args(argv)
    try:
        status, size, content_type = fetch_to_file(args.task, args.url, args.output, args.timeout, args.max_bytes)
    except (ValueError, OSError, urllib.error.URLError) as exc:
        print(f"safe-fetch: blocked/failed: {exc}")
        return 2
    print(f"safe-fetch: status={status} bytes={size} content_type={content_type} saved=private-task-workspace")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
