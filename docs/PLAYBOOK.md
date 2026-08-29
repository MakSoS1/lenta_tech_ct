# Fast CTF solving playbook

This is an on-demand reference. The always-loaded rules live in `AGENTS.md`.

## 1. Preserve the problem before exploring

Keep the exact challenge statement intact. Extract separately: category hint, provided files, official target, flag format if explicitly stated, constraints, hints and any interaction limits. Do not let later tool output replace or paraphrase away a critical condition.

## 2. Spend the first pass on discriminating evidence

Prefer cheap observations before expensive automation.

- Files: `file`, archive listing, hashes, `strings` selectively, headers/metadata.
- Native binary: architecture, `checksec`, imports/symbols, obvious strings, entry path.
- Web source: routes, auth/state boundaries, serialization, templates, upload paths, client/server trust assumptions.
- Crypto: identify primitive, attacker-known values, nonce/key reuse, algebraic structure and oracle capabilities before brute force.
- PCAP/forensics: protocol summary, endpoints, streams, timestamps and embedded objects before broad carving.
- Remote service: inspect only the official endpoint; record one minimal interaction before scripting.

## 3. Route to one specialist

Start with one skill from `ctf-skills`. The dispatcher is useful only when the category is genuinely unclear. Cross-category challenges should add skills incrementally rather than loading everything.

## 4. Hypothesis ledger

Keep at most four active hypotheses, ranked by expected value. Each experiment should answer a concrete question. After an experiment, mark the hypothesis supported, weakened or ruled out and capture the transferable observation in a few lines.

This is the practical version of NYU's planner/executor split: planning stays short, execution stays focused, and verification prevents a plausible-looking tool output from becoming an assumption.

## 5. Automate the solve path early

Once the vulnerability/transform is understood, encode it in a deterministic script. A good live solver has explicit inputs, bounded retries/timeouts, concise diagnostics and no hard-coded final flag. Store it under the ignored task workspace during the live event.

## 6. Parallelism only when it buys independence

Use Veria-style parallel solver attempts for genuinely different approaches: for example static reversing versus symbolic execution, or two distinct web vulnerability hypotheses. Share concise findings, not complete transcripts. Stop duplicate tracks once one produces decisive evidence.

## 7. Pivot deliberately

A pivot should change an assumption, attack surface, representation or tool—not merely repeat the same command with random parameters. Review what is known, what is ruled out and what evidence is missing.

## 8. Finish privately

Validate the candidate result against the intended service or challenge workflow. Keep the actual value out of repository files and public CI. Report it directly to the user.
