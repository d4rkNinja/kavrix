# Direct local CLI

Kavrix no longer uses a Kavrix API or self-hosted server for the supported path.
The CLI opens the selected local-file or MongoDB adapter itself, validates its
path or URI policy, decrypts locally with a protected key file or recovery kit,
and writes only the authenticated encrypted document.

Use the local command surface documented in [the CLI reference](./cli-reference.md).
The direct storage boundary is implemented by
`packages/storage`; CLI orchestration is in `apps/cli/src/local-vault-cli.ts`.

The old server/client/TUI workflow is historical and is not built, tested, or
included in the npm package.
