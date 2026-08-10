# Documentation engineering guide

Documentation is part of Kavrix's security contract. Keep it synchronized with
observable implementation evidence and downgrade claims immediately when a gate
or platform is not verified.

- Use `docs/implementation-status.md` as the factual feature ledger. Distinguish
  implemented, verified, in-progress, planned, and blocked work.
- Describe zero-knowledge boundaries precisely. Never claim the product protects
  against a compromised unlocked host, same-user malware, keylogging, screen or
  clipboard capture, administrator access, or server deletion/withholding.
- Keep one canonical release procedure in `docs/release.md`; other release pages
  may only redirect to it.
- Command documentation must match the actual public executable. Do not advertise
  a planned command as installed or safe.
- Record platform-specific evidence. A Windows native test is not macOS/Linux
  evidence, and a unit double is not a real MongoDB, keychain, clipboard, terminal,
  package, or restore test.
- Never put real-looking secrets, private endpoints, credentials, access tokens,
  or local filesystem state in examples.
- Link important security decisions to the owning schema, module, test, or
  authoritative upstream source where practical.

Before a release claim, reconcile the README, architecture, threat model,
cryptography, data model, CLI/TUI guides, self-hosting guide, security testing,
release guide, and implementation-status ledger with the final verified tree.
