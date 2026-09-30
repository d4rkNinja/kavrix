# Release notes — 0.2.29 one-command `.env` import (`kavrix import env`)

New adoption on-ramp for the README's core pitch — "give applications and AI
agents access to credentials without handing them your `.env`". Until now a
developer with dozens of secrets in a `.env` file had no bridge into Kavrix;
this release adds one guarded command.

## What ships

- `kavrix import env --file <path>` reads a strict `.env` file — one
  `KEY=value` per line, optional `export ` prefixes, blank lines and `#`
  comments ignored, values are the literal remainder after the first `=`
  (no quote stripping or escape processing) — and writes every entry into
  the selected database vault as flat credentials in one atomic vault
  update. The credential name is the variable name (optionally under
  `--prefix <prefix>`, for example `--prefix prod/` imports `AWS_KEY` as
  `prod/AWS_KEY`); the value is the variable's value. The whole document
  is parsed and every name validated before any unlock material is
  requested, so a malformed file fails closed with its line number without
  prompting. Duplicate variables, keys with whitespace or control
  characters, reserved names, and hostile name shapes are refused; missing
  selection fails with the standard vault-selection message before any
  prompt.
- Conflicts fail the entire import (exit 1, first conflicting name in the
  message) unless `--overwrite` is explicit; nothing is written unless the
  whole batch passes. The summary prints counts and names only — values
  are never echoed to any output stream.
- Scope: database-container profiles (file and MongoDB, with the standard
  routing options including `--vault`, `--session`, and `--passphrase-stdin`
  / `--database-url-stdin` frames). Legacy version 2 vaults are refused.
  Bounded at 1 MiB per file and 500 variables per import.
- Source-file hygiene: after a fully successful import on an interactive
  TTY the command asks `Delete <path>? (y/N)`; `--delete-source` performs
  the deletion without asking in controlled automation. The file is
  shredded before unlink — full-length random overwrite, truncate, close,
  then removal — best effort in JavaScript. A declined prompt, a non-TTY
  run without the flag, or a failed deletion leaves the file in place and
  reports `sourceDeleted: false` (with a warning when deletion failed).

## Implementation

- `apps/cli/src/import-env-command.ts` — strict parser, guarded naming
  rules, one batched `session.updateVault` write, and the
  shred-then-unlink hygiene flow.
- `apps/cli/test/import-env-command.test.ts` — end-to-end against the real
  CLI composition: import → `get --reveal` round-trip per variable under a
  prefix, ambient credentials untouched, conflict refusal then
  `--overwrite` success, malformed and duplicate files failing before any
  prompt, reserved and whitespace names refused, `--delete-source` shred
  with the data still readable afterward, and a canary sweep proving
  values never reach stdout or stderr.
