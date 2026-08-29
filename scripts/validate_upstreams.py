#!/usr/bin/env python3
"""Validate the immutable allowlist of CTF upstream repositories."""

from __future__ import annotations

import argparse
import json
import pathlib
import re


EXPECTED_UPSTREAMS = {
    "ctf-skills": {
        "url": "https://github.com/ljagiello/ctf-skills.git",
        "sha": "36c72e53a96a035791821caff7440882ea0f5c57",
        "role": "runtime",
    },
    "ctf-agent": {
        "url": "https://github.com/verialabs/ctf-agent.git",
        "sha": "3366d569557c4fda3fd153040632de65e255396d",
        "role": "runtime",
    },
    "nus-workstation": {
        "url": "https://github.com/NUSGreyhats/ctf-agent-workstation.git",
        "sha": "129a7902b0241c20469f21ea544b6973d995556b",
        "role": "reference",
    },
    "nyu-dcipher": {
        "url": "https://github.com/NYU-LLM-CTF/nyuctf_agents.git",
        "sha": "612190f298ae9e604f00370019beed4ba1f372f6",
        "role": "reference",
    },
}

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/+@-]+$")


def validate_lock_data(data: object) -> dict[str, dict[str, object]]:
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("lock file must be an object with version=1")
    entries = data.get("upstreams")
    if not isinstance(entries, list):
        raise ValueError("upstreams must be a list")

    validated: dict[str, dict[str, object]] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise ValueError("each upstream must be an object")
        name = raw.get("name")
        if not isinstance(name, str) or name not in EXPECTED_UPSTREAMS:
            raise ValueError(f"unknown upstream name: {name!r}")
        if name in validated:
            raise ValueError(f"duplicate upstream: {name}")
        expected = EXPECTED_UPSTREAMS[name]
        for key in ("url", "sha", "role"):
            if raw.get(key) != expected[key]:
                raise ValueError(f"{name}: {key} must exactly match the repository allowlist")
        sha = raw["sha"]
        if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
            raise ValueError(f"{name}: sha must be an immutable 40-hex commit")
        paths = raw.get("expected_paths")
        if not isinstance(paths, list) or not paths:
            raise ValueError(f"{name}: expected_paths must be a non-empty list")
        for item in paths:
            if (
                not isinstance(item, str)
                or item.startswith("/")
                or ".." in pathlib.PurePosixPath(item).parts
                or not _SAFE_PATH_RE.fullmatch(item)
            ):
                raise ValueError(f"{name}: unsafe expected path: {item!r}")
        validated[name] = dict(raw)

    if set(validated) != set(EXPECTED_UPSTREAMS):
        missing = sorted(set(EXPECTED_UPSTREAMS) - set(validated))
        extra = sorted(set(validated) - set(EXPECTED_UPSTREAMS))
        raise ValueError(f"lock must contain exactly the allowlist; missing={missing}, extra={extra}")
    return validated


def load_lock(path: pathlib.Path) -> dict[str, dict[str, object]]:
    return validate_lock_data(json.loads(path.read_text(encoding="utf-8")))


def main(argv: list[str] | None = None) -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", default=str(root / "config" / "upstreams.lock.json"))
    parser.add_argument("--emit", choices=("none", "runtime", "reference", "all"), default="none")
    args = parser.parse_args(argv)
    entries = load_lock(pathlib.Path(args.lock))
    if args.emit != "none":
        for name in EXPECTED_UPSTREAMS:
            entry = entries[name]
            role = str(entry["role"])
            if args.emit != "all" and role != args.emit:
                continue
            paths = ",".join(str(p) for p in entry["expected_paths"])
            print(f"{name}\t{entry['url']}\t{entry['sha']}\t{role}\t{paths}")
    else:
        print(f"upstream-lock: valid {len(entries)} pinned repositories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
