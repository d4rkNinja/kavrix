# Contributing to Kavrix

Thank you for helping improve Kavrix. Credential-vault changes have an unusually
high cost when they are wrong, so small, reviewable patches and explicit evidence
are preferred over broad rewrites.

Read [AGENTS.md](./AGENTS.md) before changing code. Security-sensitive behavior
must also be consistent with `docs/threat-model.md` and `docs/cryptography.md`.

## Development setup

Requirements:

- Node.js 24.19.x, matching `.nvmrc` (the oldest LTS marking built-in Argon2
  stable). The published CLI supports the wider `>=24.12.0 <25 || >=25.1.0`;
  contributors stay on one baseline so gate results are comparable, and CI
  covers the rest of the range.
- pnpm 11 through Corepack

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm verify
pnpm test:coverage
```

## Pull requests

- Explain the observable behavior and security impact.
- Add tests that fail without the change, including negative/tampering cases when
  a trust boundary is involved.
- Do not place real credentials, realistic private keys, tokens, vault files, or
  secret-bearing logs in issues, fixtures, snapshots, or commits.
- Do not weaken assertions, redaction, validation, permissions, or cryptographic
  parameters to make a test pass.
- Update the architecture/security documentation and implementation status when
  behavior changes.

Use clearly fake values such as `example.invalid` and generated test-only byte
sequences. Report vulnerabilities privately using the process in `SECURITY.md`.
