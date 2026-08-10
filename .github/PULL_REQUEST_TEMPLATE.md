## What changed

Describe the user-visible behavior and why this approach is appropriate.

## Security impact

Describe affected trust boundaries, secret-handling paths, and failure behavior.
Write `None` only when the change cannot affect them.

## Verification

- [ ] `pnpm verify`
- [ ] `pnpm test:coverage`
- [ ] `pnpm audit --audit-level high`
- [ ] New behavior has positive and negative tests
- [ ] Real MongoDB/keychain/platform integration gates ran when the change affects them
- [ ] No real secrets or secret-bearing logs are included
- [ ] Documentation and implementation status are accurate
- [ ] A changeset is included when publishable behavior changes
