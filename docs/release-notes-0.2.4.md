# Kavrix 0.2.4 — Broker bounds and operator-surface corrections

Kavrix 0.2.4 is a patch release that hardens the local agent broker, corrects
the first-run operator surface, and aligns the CLI and website documentation.

## Security and reliability

- The local agent broker keeps requests serialized while bounding how long a
  request may wait for the session queue. Requests that cannot acquire the
  queue promptly fail closed with a retryable busy result.
- Client frame rate, queued depth, and pending-frame resources are bounded.
  Connections that exceed those limits are torn down with a resource-limit
  result and the broker preserves its required exit-frame handling where the
  connection is still writable.
- The wire contract remains the existing version-one broker frame contract;
  this patch adds resource bounds around it rather than a new IPC service.
- NDJSON input is measured in bytes and rejected above 2 MiB. Relay data is
  capped at 512 KiB decoded per frame, with at most 64 pending frames / 4 MiB
  before the child is ready and a 4 MiB active child-stdin buffer bound.
  Backpressure pauses the broker socket until the child drains.

## Operator and documentation corrections

- The canonical first-run path is consistent across the README, security
  policy, command guide, release notes, homepage, quickstart, command reference,
  automation page, and footer: profile → `db init` → `db vault create`, with the
  file datastore first-class and MongoDB optional.
- Bare interactive `kavrix init` creates a protected, non-secret onboarding
  reference. The CLI and documentation now say explicitly that current commands
  do not load edited `config.toml` values automatically.
- Database recovery and agent examples now include their required options.
  MongoDB visibility text distinguishes visible database/collection namespaces
  from encrypted Kavrix database, vault, and credential labels.
- Website changelog rendering keeps visible and copied package pins exact while
  preventing a contiguous `kavrix@<version>` token in raw HTML, avoiding
  Cloudflare email-obfuscation rewrites.
- Removed the now-unused `smol-toml` development dependency. A current
  moderate-severity audit reports no known vulnerabilities.

## Local verification

The following evidence was collected on Windows on 27 August 2026:

- `pnpm verify:all`: formatting, lint, typecheck, build, the complete unit suite
  (`120m 7s`), packed all-command acceptance (`4m 34s`), and package smoke
  (`22.4s`) passed. Docker-backed database-container acceptance was skipped
  because Docker is unavailable on this host.
- After removing the unused parser, formatting, lint, typecheck, build, packed
  all-command acceptance, package smoke, and `pnpm --filter kavrix pack:check`
  were re-run and passed. The dry run produced `kavrix-0.2.4.tgz` with only the
  allowlisted compiled artifacts, declarations, SBOM, license, package metadata,
  and README.
- Focused regressions passed: broker protocol `8/8`, onboarding command `12/12`,
  queue timeout/depth overload, concurrent serialization, and authenticated
  relay rate/size teardown.
- `pnpm audit --audit-level moderate`: `No known vulnerabilities found`.
- Website `lint`, `typecheck`, and production `build` passed. Browser checks at
  desktop and 390 × 844 confirmed the canonical command content, required
  options, visible MongoDB metadata wording, clean console/error state, and
  `kavrix@0.1.3` visible in page text but absent as a contiguous raw-HTML token.

## Release gates

Publication remains fail-closed: the `v0.2.4` trusted-publishing workflow must
confirm that the tagged commit is on `main`, has successful exact-SHA CI and
CodeQL runs, passes the full Linux release validation (including the
Docker-backed database-container suite), and matches the inspected npm archive
before it creates the GitHub release.
