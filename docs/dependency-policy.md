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

## Reviewed application and build dependencies

The following direct versions were reviewed against their published manifests and
upstream repositories on 2026-08-10. This records why they are present; it does not
replace advisory review at each upgrade.

### Client cryptography

- [`libsodium-wrappers` 0.8.4](https://github.com/jedisct1/libsodium.js) is the
  ISC-licensed standard WebAssembly/JavaScript wrapper used in the client-side
  cryptography graph for XChaCha20-Poly1305-IETF and secretstream. The prepared
  public CLI also bundles it for protected portable-key files; metadata-only
  commands do not evaluate its lazy chunk. The standard build contains those
  reviewed capabilities; the larger `-sumo` build is deliberately excluded
  because its extra low-level/deprecated surface is not required. Kavrix waits
  for `sodium.ready`, validates every input and output at its own boundary, frees
  secretstream state in `finally`, and tests tampering, context transplantation,
  truncation, and bounded streaming. The package has no install script; its sole
  runtime dependency is the corresponding ISC-licensed `libsodium` 0.8.4
  distribution. Both are bundled npm-library components in the public SBOM.
  Replacing them requires a compatible, reviewed XChaCha and secretstream
  implementation plus all existing golden/adversarial tests.

### Server and persistence

- [`fastify` 5.11.0](https://github.com/fastify/fastify/tree/v5.11.0) is the API's
  MIT-licensed HTTP lifecycle and routing implementation. Reimplementing request
  parsing, body limits, proxy handling, and response serialization would add a
  larger security surface. It has a material pure-JavaScript dependency tree, so
  Kavrix pins the resolved graph, rejects unexpected bodies before handlers, uses
  explicit proxy ranges, and keeps request bodies and authorization headers out of
  logs. The exit path is another maintained Node HTTP framework behind the same
  API ports and canonical schemas.
- [`mongodb` 7.5.0](https://github.com/mongodb/node-mongodb-native/tree/v7.5.0)
  is the Apache-2.0 official Node driver. Kavrix needs sessions, replica-set
  transactions, validators, indexes, and BSON behavior that the standard library
  does not provide. The driver has three direct JavaScript dependencies and no
  client-side decryption role. MongoDB integration CI runs against the official
  8.0.26 image pinned by manifest digest. Replacing the driver means implementing
  the same ciphertext-only storage port and rerunning transaction/canary evidence.
- [`zod` 4.4.3](https://github.com/colinhacks/zod/tree/v4.4.3) is the MIT-licensed,
  dependency-free source of canonical runtime validation and inferred TypeScript
  contracts. Untrusted HTTP, persistence, CLI, backup, and sync data must cross a
  schema boundary. An exit requires a single canonical-schema migration rather
  than adding parallel hand-written interfaces.

### Terminal applications

- [`commander` 15.0.0](https://github.com/tj/commander.js/tree/v15.0.0) is the
  MIT-licensed, dependency-free CLI parser. Kavrix uses descriptors to register
  commands and suppresses value-reflecting parser errors. It does not receive
  portable keys or passphrases as arguments. The public executable bundles this
  code and includes its full license notice.
- [`ink` 7.1.1](https://github.com/vadimdemedes/ink/tree/v7.1.1) and its React
  peer provide declarative terminal rendering for dynamic schema-driven screens.
  Its larger dependency graph includes ANSI, layout, terminal, and WebSocket
  utilities, so all rendered text still passes Kavrix's control-sequence sanitizer
  and reveal policy. Ink is not loaded by the currently packed public executable;
  enabling it there requires packed-bin and real-terminal tests on all claimed
  platforms. The exit is the same TUI state model rendered by another adapter.

### Public package bundler

[`esbuild` 0.28.1](https://github.com/evanw/esbuild/tree/v0.28.1) is a pinned,
MIT-licensed build-only dependency used to produce a self-contained ESM `creds`
entry and deterministic content-hashed lazy chunks. Bundling is required because
the public `kavrix` package must not install unpublished private workspace
packages. Its platform binary uses an install/build step, so `esbuild` is the
sole entry in `allowBuilds`; upgrades require reviewing the release binaries and
rebuilding on Windows, macOS, and Linux. The build embeds full Commander, Zod,
`libsodium-wrappers`, and `libsodium` license notices, emits inline source maps
without source contents, rejects external non-Node imports and fixture canaries,
and generates a deterministic CycloneDX 1.6 SBOM with an aggregate artifact-set
hash and one named hash for every emitted JavaScript artifact. The TypeScript
compiler remains the type/declaration authority; if esbuild becomes unmaintained,
a replacement must reproduce these artifact checks before removal.

### Native keychain adapter

`@napi-rs/keyring` 1.3.0 is the optional native adapter for macOS Keychain,
Windows Credential Manager, and Linux Secret Service. It is MIT licensed, has no
JavaScript dependencies or install script, publishes platform-specific N-API
binaries, and was active at the 2026-08-10 review. It replaces the archived
`keytar`; Kavrix uses only its byte-oriented asynchronous entry API. Loading or
using it may fail on headless or misconfigured systems. Callers must then request
the portable key again—there is deliberately no file or command-line fallback.

The default suite exercises the adapter boundary without touching the user's
credential store. Cross-platform CI must explicitly set
`KAVRIX_KEYCHAIN_INTEGRATION=1` to run the real create/read/delete smoke test. An
upgrade requires reviewing the Rust `keyring` backend, every shipped native
artifact, platform support, advisories, and the handling of byte buffers.

### Opt-in native platform acceptance

The repository-wide `pnpm platform:acceptance` command is the authoritative
opt-in gate for real keychain, key-file, and clipboard behavior. It requires
all four values below to be exactly `1` before it starts Vitest:

```text
KAVRIX_KEYCHAIN_INTEGRATION=1
KAVRIX_KEY_FILE_INTEGRATION=1
KAVRIX_CLIPBOARD_INTEGRATION=1
KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION=1
```

The gate runs the native keychain round trips, the generated protected-key-file
permission/link checks, and the exclusive clipboard snapshot/copy/guarded-clear
restore test. It invokes an explicit file list with bounded shell-free child
execution and rejects skipped, pending, todo, failed, malformed, or incomplete
reports. It is deliberately absent from ordinary `pnpm test`: the clipboard
test temporarily replaces user clipboard content, and native stores require an
OS account/session with a usable credential service. A missing native service,
desktop clipboard, ACL capability, or Unix permission capability is a failed
acceptance prerequisite, never evidence for a fallback or a passing platform
claim.

### Embedded third-party material

The passphrase generator embeds EFF Short Wordlist #1 (1,296 entries) from
[EFF's source list](https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt)
and documented [methodology](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases).
The downloaded UTF-8/LF source before dice-code removal was independently
checked on 2026-08-10 as SHA-256
`8f5ca830b8bffb6fe39c9736c024a00a6a6411adb3f83a9be8bfeeb6e067ae69`.
EFF's [copyright policy](https://www.eff.org/copyright) licenses its original
website material under CC BY 4.0 unless noted otherwise. The source attribution
must remain with the embedded list, and any public bundle containing it must
ship the corresponding attribution/license notice. The public CycloneDX SBOM
records it as a separate `data` component with CC-BY-4.0, a stable non-hash
bom-ref, the authoritative source reference, and the reviewed source digest as a
named property rather than pretending it hashes the transformed embedded array.
The list is data only; generation performs no network I/O.

## Ongoing checks

- ESLint enforces package direction: schemas cannot import another Kavrix
  package; core cannot import outer adapters; sync remains schema-only; and the
  API/storage production graph cannot import client crypto, key, clipboard,
  backup, runner, local-state, or TUI capabilities.
- `pnpm audit --audit-level high` runs in CI.
- GitHub dependency review rejects newly introduced high-severity advisories and
  copyleft licenses incompatible with the MIT distribution.
- CodeQL's JavaScript/TypeScript action is pinned to the reviewed `v4.37.3`
  commit. It is skipped while the repository is private unless private CodeQL
  is explicitly enabled with repository variable
  `KAVRIX_PRIVATE_CODEQL_ENABLED=true`; it must produce a successful result
  before release.
- Release review inspects `pnpm-lock.yaml`, install scripts, license output, and
  the exact `npm pack` contents.
- Passing an advisory database check does not establish that a dependency or the
  product is secure.

Security-sensitive choices and their trade-offs are documented in
`docs/cryptography.md` and `docs/implementation-status.md`.
