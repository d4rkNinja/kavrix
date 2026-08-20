# Active release boundary

Kavrix currently releases one public package, `kavrix`, and the four private
workspace packages it needs to build and test that package:

- `apps/cli` (`kavrix`)
- `packages/schemas` (`@kavrix/schemas`)
- `packages/crypto` (`@kavrix/crypto`)
- `packages/key-files` (`@kavrix/key-files`)
- `packages/storage` (`@kavrix/storage`)

The source trees for `packages/client`, `packages/clipboard`, `packages/core`,
`packages/import-export`, `packages/keychain`, `packages/local-store`,
`packages/runner`, `packages/sync`, and `packages/tui` are parked/incubating.
They remain available for future work, but are deliberately absent from
`pnpm-workspace.yaml`. They are not release packages, are not built by the
active workspace gates, and must not be described as shipped or verified.

## Active verification commands

From the repository root, the active release checks are:

```sh
pnpm changeset status
pnpm build
pnpm test
pnpm test:coverage
pnpm format:check
pnpm lint
pnpm typecheck
```

The root Vitest configuration includes the active CLI, schema, crypto, key-file,
and storage tests. In particular, the portable-key and revision-anchor suites
are part of the active security gate. Coverage is collected only from the five
active source trees and uses the configured thresholds.

The packed CLI, database-container acceptance, package allowlist, and audit
checks remain required release gates. MongoDB integration requires an
authorized disposable transaction-capable replica set. Native Windows ACL
results are Windows evidence; a macOS or Linux pass does not substitute for it.
