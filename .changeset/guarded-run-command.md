---
'kavrix': minor
---

Expose `creds run` in the public executable.

Each `--env NAME=group/credential/field[#index]` mapping releases one authorized
field into the named destination variable of one directly spawned child. The
child is started with an argument array and `shell: false`, never through a
shell, and the command refuses to start if a released value appears in the
executable path or any argument. Its environment holds only the mapped
destinations plus the parent variables explicitly named by `--inherit`;
destination names the runner reserves, duplicate names after upper-casing, and
malformed mappings fail as usage before any vault is unlocked. `--cwd`,
`--timeout`, and `--max-output` bound the working directory, wall-clock time, and
per-stream capture, and captured output is redacted byte-for-byte — including a
released value cut in half by the capture limit. `--dry-run` validates the whole
invocation and prints the plan without unlocking the vault or reading a field.

Every argument after `<executable>` is relayed verbatim, so this command's own
options must precede it; a single leading `--` is accepted and consumed, and any
later `--` belongs to the program. A child that does not finish normally exits
with `RUN_CHILD_FAILED` and code `1` after its exit code, signal, and termination
reason have been reported.

Two limits belong to the operating system and are documented rather than claimed
away: termination reaches only the spawned process, so an already-forked
descendant survives a timeout, abort, or output-limit kill; and Windows copies a
fixed set of shell variables into every child regardless of the environment
supplied here, none of which carry a released value.
