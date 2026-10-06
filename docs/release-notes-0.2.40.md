# Release notes — 0.2.40 every-command startup and execution performance

The main change in this release is how much work a command does before it
starts serving you. Every command's parser, options, and help text load
immediately, while that command's implementation loads only after the
arguments parse. `kavrix --version`, `--help`, usage errors, and unknown
commands never load command implementations at all, and no command pays for
code it does not use. This applies to the whole command surface — quick reads,
JSON views, writes, renames, doctor, recovery, database-container, backup,
import, self-update, and the interactive TUI — not to a few selected commands.
Stable exit codes moved into a schema-free module so failure classification
stays on the slim path.

On Windows, the first protected-file operation pays a one-time helper
interpreter boot. The CLI now starts that helper while it is still reading
arguments and unlock input, so the boot overlaps work the command would wait
for anyway. The warm-up never verifies anything and cannot turn a later
failure into success; if the helper cannot start, the first real request
starts it again and fails closed as before.

Repeated work inside one operation is now reused without weakening any
verification. Local vault and database-container reads parse and verify once
per store session and are then served from the verified copy after a single
confirming metadata check; any metadata change falls back to the full
verification path. Permission checks reuse a prior verification only while the
file's metadata snapshot is unchanged, and a published write is recorded so
the next read skips a redundant full parse while the published-file readback
still byte-compares staged and on-disk content. Cryptographic paths build
authenticated contexts once per operation and stop copying secret buffers
through intermediate parses. The interactive TUI renders large vaults through
windowed lists, cached screen models, and a calmer frame clock, and the
executable enables Node's compile cache before loading the module graph.

Unlock cost is deliberately unchanged. Argon2id parameters, encrypted
envelope formats, ACL and ownership verification, atomic publication, and
fail-closed behavior are identical to 0.2.39; nothing was removed or weakened
to gain speed.

Measured locally on Windows against a disposable vault fixture (medians of
cold real-command runs; these are local measurements, not latency promises):
`kavrix --version` fell from about 166 ms to 76 ms, unlocked `vault get` from
about 695 ms to 595 ms, and a put-and-remove round trip from about
1517 ms to 1302 ms. The remaining cost of a real command is dominated by the
deliberate Argon2id unlock derivation and the cold helper interpreter boot.
The full scenario table and methodology are in
[performance.md](performance.md).

No encrypted vault, portable-key, recovery-kit, profile, or cryptographic
envelope format changed in this release. Cross-platform CI, CodeQL, full
local release gates, trusted npm publication, archive-integrity
reconciliation, and GitHub release verification must finish before
publication is claimed. See the [canonical release procedure](release.md).
JavaScript cannot guarantee erasure of string copies, and these changes do
not protect an unlocked host from same-user malware or administrator access.
