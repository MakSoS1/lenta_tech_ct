# Live CTF operating procedure

The GitHub repository is public, so a live branch is public too. **Do not push live solution code** during the competition. Do not push challenge files, private notes, exploit transcripts, candidate values or final flags.

## When a new task arrives in chat

1. Keep the exact user-provided statement and attachments as the source of truth.
2. Use the repository's `AGENTS.md` contract and the smallest relevant linked skill.
3. Create a private task directory with `./scripts/new_task.sh TASK` when a local checkout is being used.
4. Put downloaded/extracted challenge material under `.ctf-work/TASK/files/`.
5. Register only the official endpoint supplied by the user/organizer.
6. Run static triage or the no-network sandbox first.
7. Keep solver/exploit work under `.ctf-work/TASK/scratch/` during the event.
8. Keep tool output under `.ctf-work/TASK/output/`; summarize concise findings in the private notes.
9. If a candidate flag is recovered, return it directly in the private chat and do not write it into tracked files.

## Using GitHub Actions during the event

Actions may preflight the repository, build the toolbox and verify pinned upstreams. They are not a private compute channel for live solves. Do not pass live challenge secrets or values into workflow inputs, environment variables, summaries or artifacts.

If heavy compute is needed for a live solve, use the local/disposable sandbox outside public Actions. After the competition, sanitized solver code and writeups can be committed after running the repository secret scan.

## After a solve

Keep a tiny private findings record so another attempt does not repeat work: category, decisive vulnerability/observation, solver path, failed approaches worth remembering, and any environment-specific caveat. Do not copy large logs into the model context.
