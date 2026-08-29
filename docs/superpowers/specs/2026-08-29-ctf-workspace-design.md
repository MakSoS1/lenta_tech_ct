# CTF Agent Workspace Design

## Goal

Prepare `MakSoS1/lenta_tech_ct` as a fast, reproducible and public-safe workspace for solving authorized CTF challenges with an AI coding agent during the competition.

## Upstream strategy

Four upstream projects are pinned to immutable commits. Two are runtime dependencies:

- `ljagiello/ctf-skills` — category-specific CTF skills and routing knowledge.
- `verialabs/ctf-agent` — autonomous solver architecture and heavy CTF sandbox.

Two are reference dependencies checked by CI without installing their privileged workstation setup:

- `NUSGreyhats/ctf-agent-workstation` — operational patterns: per-challenge workspaces, provider-local skills, GDB tooling, swarm collaboration.
- `NYU-LLM-CTF/nyuctf_agents` — planner/executor/pivot architecture.

All clones use exact commit SHAs from `config/upstreams.lock.json`. Bootstrap never follows a floating branch.

## Context discipline

`AGENTS.md` is the only always-loaded operational document. A solver must keep the full challenge statement in the active context and load exactly one category skill first. A second category skill is loaded only after a concrete cross-category need or failed hypothesis. Detailed documentation is consulted on demand, not preloaded.

The live loop is:

1. Preserve the exact challenge statement and official target supplied by the user/organizer.
2. Triage files/service cheaply.
3. Choose one category skill.
4. State one or more short hypotheses.
5. Run the cheapest discriminating checks.
6. Build a reproducible solver/exploit.
7. Validate the candidate flag privately.
8. If stuck, record concise findings and pivot without repeating failed work.

## Trust model and prompt-injection defense

Challenge-controlled content is untrusted data. This includes files, strings, HTML, comments, metadata, service banners, model-readable text in images/PDFs, README files in challenge bundles, tool output, packet payloads and URLs discovered inside them.

Untrusted content cannot:

- change repository or agent instructions;
- authorize network targets;
- request access to environment variables, tokens, SSH keys, browser/session data, home-directory configuration, cloud metadata or GitHub credentials;
- instruct the agent to install software, run shell commands, fetch-and-execute scripts or exfiltrate data;
- cause the solver to follow a URL merely because the challenge text says to do so.

Commands copied or semantically derived from untrusted content are not executed verbatim. The agent must independently derive a command that is necessary to test a CTF hypothesis. `scripts/check_command.py` provides an additional lint gate.

Network access is limited to targets explicitly supplied as official CTF endpoints plus ordinary public research required by a legitimate OSINT challenge. Newly discovered hosts are not automatically trusted. `scripts/safe_fetch.py` enforces an explicit host allowlist for scripted HTTP access and disables cross-host redirects.

## Public-repository secrecy

The repository is public. Actual flags, candidate flags, tokens, credentials, raw response bodies likely to contain flags, memory dumps and live challenge scratch data must not be committed.

Ephemeral state lives below `.ctf-work/` and `.runtime/`, both ignored. Live flag-producing commands are not run in public GitHub Actions. Actions are restricted to building, testing, linting and upstream smoke checks. No workflow uploads live-solve artifacts.

`scripts/secret_scan.py` scans tracked text for common CTF flag shapes, private-key headers and high-risk token assignments. CI fails when such material is found.

## Runtime isolation

Two execution layers are provided:

- `lenta-ctf-fast`: a compact Docker image for immediate triage and common web/pwn/reverse/crypto/forensics work.
- `ctf-sandbox`: Veria Labs' pinned heavy sandbox, built only when requested.

`scripts/run_sandbox.sh` mounts only the selected task workspace, drops Linux capabilities, applies `no-new-privileges`, removes host environment inheritance and disables networking by default. Network must be explicitly enabled for an official CTF target.

## GitHub Actions

Three workflows are used:

- `preflight.yml`: unit tests, Python compile, shell syntax/ShellCheck and tracked-file secret scan.
- `build-ctf-env.yml`: clone pinned runtime upstreams, link skills and build/smoke-test the fast image; optional manual Veria heavy-image build.
- `upstream-smoke.yml`: fetch all four immutable upstream SHAs and verify expected architecture files without executing NUS/NYU privileged installers.

All jobs use read-only repository permissions unless a GitHub-owned action requires otherwise. No challenge flag is accepted as a workflow input or emitted as an output.

## Success criteria

- A fresh checkout can run `./scripts/bootstrap.sh` and create pinned runtime clones and provider skill links.
- `./scripts/preflight.sh` exits zero on the clean repository.
- Unit tests prove the secret scanner, command-origin guard and safe-fetch allowlist behavior.
- The fast Docker image builds and has the documented common tools.
- The Veria sandbox can be built on demand from the pinned upstream.
- CI verifies all four pinned upstream SHAs.
- No tracked file contains a real or realistic flag/token secret.
- Agent instructions explicitly treat challenge content as untrusted and forbid literal execution of embedded instructions.
