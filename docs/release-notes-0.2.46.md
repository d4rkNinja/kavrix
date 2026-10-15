# Release notes — 0.2.46

This patch increments the checkout's 0.2.45 version by 0.0.1. Local release
verification passed; publication requires exact-commit CI and CodeQL followed
by trusted publishing, as described in [the release procedure](release.md).

- Home arrow keys and page movement now follow the displayed section order.
  Previously, moving down from Recovery selected Run before Policy even though
  Policy appeared above Run. Digit shortcuts and mouse targets keep their
  original destination indexes.
- Home reuses its static grouped navigation rows. The command palette reuses
  descriptors by screen and builds its row-index lookup once per render.
  Blocked actions still evaluate the current state, including unlock status.
- Credential search normalizes names once per immutable credentials list,
  instead of on every new query. Refreshing the list replaces the weakly owned
  name index; the existing result cache remains bounded to 32 queries. Neither
  cache stores decrypted credential values.
- Fullscreen layout tests explicitly select their terminal mode, so running
  them from a dumb terminal does not accidentally exercise line-oriented output.
- The existing performance harness now converts milliseconds to operations per
  second correctly; its previous throughput figures were inflated by 1,000.
- Manual publication retries can no longer bypass exact-commit CI or the packed
  smoke test. Both CI and CodeQL remain mandatory on every publication path.
- The TUI timeout test's stand-in child derives its marker path from its own
  module URL instead of interpolating a filesystem path into generated code,
  addressing CodeQL's code-sanitization alert without changing the timeout or
  child-termination assertions.
- The deployment workflow uses double-quote formatting to match its automated
  branch-dropdown updater, preventing that updater from reintroducing the
  formatting failure that blocked the previous CI run.

## Performance evidence

`pnpm exec tsx scripts/perf/bench-app-selectors.mjs` uses synthetic metadata,
10,000 names, and successive queries that exceed the result-cache limit. On the
Windows development host, mean search time changed from approximately 0.293 ms
to 0.195 ms per query; command lookup changed from approximately 0.00093 ms to
0.0000067 ms. These are local selector timings, not whole-terminal latency or a
cross-platform guarantee. The benchmark is retained for reproduction.

## Verification status

Regression tests reproduce the original out-of-order Home movement and cover
forward/reverse movement, page movement, activation, stable mouse indexes,
current-state command blocking, and refreshed search data. Three publication
workflow regression tests enforce the mandatory retry gates.

Windows local verification passed frozen-lockfile installation, build,
formatting, lint, type checking, the full unit/integration suite, coverage,
packed-package smoke and allowlist/SBOM inspection, all-command local-file
acceptance, database-container acceptance, note/history executable smoke, CLI
source inclusion, and the high-severity dependency audit (no known
vulnerabilities). Coverage includes 2,209 passing tests and 21 skipped tests:
86.77% statements, 80.31% branches, 91.15% functions, and 88.33% lines. No gate or
coverage threshold was reduced. Skipped tests are not verification evidence.

No encryption format, authorization policy, or explicit reveal requirement
changes. Local Windows evidence does not establish Linux, macOS, or live MongoDB
verification; the release CI must supply its own platform evidence.
