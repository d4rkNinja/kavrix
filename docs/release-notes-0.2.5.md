# Kavrix 0.2.5 — Read-only policy developer tooling

Kavrix 0.2.5 adds a read-only workflow for developing, reviewing, and narrowing
credential-firewall policies without reading credential payloads or applying
policy changes.

## Policy developer experience

- `kavrix policy check` simulates a command and reports allow, deny, or
  confirmation-required without reading the referenced credential, consuming a
  grant, or appending an audit event.
- `kavrix policy explain` adds an ordered trace of the matching deny, command,
  executable-hash, working-directory, execution-window TTL, and confirmation
  rules.
- `kavrix policy lint` detects shadowed allow rules, impossible or ineffective
  settings, heuristically broad policies, and retained expired grants.
- `kavrix policy diff` classifies a proposed policy definition as tightening,
  widening, or otherwise changing without applying it.
- `kavrix policy suggest` derives review-only command-allowlist narrowing ideas
  from positive, sanitized events in the bounded audit ring. Suggestions are
  never applied automatically.
- `kavrix grant show` and expanded grant listings report live status, remaining
  uses, expiry, and effective restrictions without reading the credential.

## Security boundary

Read-only inspection authenticates the key binding, current database metadata,
exact local revision anchor, and sealed authorization sidecar. It opens no
catalog or vault payload, creates no missing sidecar, does not rewrite sidecar
bytes, and does not mutate audit or grant state. Credential existence and
ciphertext integrity remain deliberately deferred to the first operation that
actually requests credential data, which performs the full authenticated open
and fails closed on absence or corruption.

Policy simulation resolves and hashes the executable just as a real run does,
but it never spawns the process. Clock regression, malformed metadata, anchor
mismatch, missing authorization state, and evaluation ambiguity fail closed.
Real execution now binds explicit credential mappings to the selected policy
set and applies stored denies to selected policy credentials even when no
credential is injected, preventing a policy for one credential from being used
as cover for another.

## Release verification

The release is gated by the complete local preflight, exact-commit CI and
CodeQL, the trusted-publishing workflow's Linux verification and package
inspection, npm OIDC publication with provenance, registry SHA-512 integrity
reconciliation, and creation of the GitHub release only after npm confirms
`kavrix@0.2.5`.
