# Dependency policy

Kavrix minimizes runtime dependencies, especially packages that process secrets,
execute install scripts, load native binaries, or cross a network boundary.

## Admission criteria

Before adding a dependency, record:

1. The capability that cannot reasonably be implemented with the Node.js standard
   library or an existing dependency.
2. The upstream repository, license, release cadence, supported Node/platform
   matrix, and maintainer activity.
3. Published advisories and unresolved security issues relevant to the use case.
4. Transitive dependency count, install scripts, downloaded binaries, and native
   compilation requirements.
5. How untrusted input reaches the dependency and which tests prove safe failure.
6. The exit plan if maintenance stops.

Version ranges are resolved into and committed through `pnpm-lock.yaml`. Direct
dependencies use exact versions or the workspace catalog. Renovation is a review
event, not an automatic merge.

New versions normally cool for seven days (`minimumReleaseAge: 10080`). An
exception must name one exact version and document why waiting is riskier. The
initial exception is `nanoid@3.3.17`: the previous eligible release is affected
by GHSA-2v37-7h3g-55p8, while 3.3.17 is the first patched 3.x release compatible
with the transitive consumer. Package-wide or wildcard exceptions are forbidden.

## Install scripts

pnpm blocks dependency build scripts unless the exact package is listed under
`allowBuilds` in `pnpm-workspace.yaml`. Each addition requires source and release
artifact review. The initial allowlist contains only `esbuild`, a build dependency
of the test toolchain.

Native secret-handling dependencies receive additional scrutiny because prebuilt
binaries expand the supply-chain and platform-support surface. CI must exercise
every claimed platform; a successful JavaScript unit test on one OS is not enough.

## Ongoing checks

- `pnpm audit --audit-level high` runs in CI.
- GitHub dependency review rejects newly introduced high-severity advisories and
  copyleft licenses incompatible with the MIT distribution.
- Release review inspects `pnpm-lock.yaml`, install scripts, license output, and
  the exact `npm pack` contents.
- Passing an advisory database check does not establish that a dependency or the
  product is secure.

Security-sensitive choices and their trade-offs are documented in
`docs/cryptography.md` and `docs/implementation-status.md`.
