# Public release process

Kavrix is prepared for package verification but has not been published. On
2026-08-10 the public npm registry returned `E404` for
[`kavrix`](https://registry.npmjs.org/kavrix). That is evidence that no public
package was visible at that time; it does not reserve the name or establish npm
ownership.

## One-time blockers

Before the first release, maintainers must establish the `kavrix` package under
the intended npm organization/account, configure npm trusted publishing for the
exact public repository `d4rkNinja/kavrix`, workflow `publish.yml`, and GitHub
environment `npm`, and protect that environment with maintainer approval. npm's
[trusted-publisher configuration](https://docs.npmjs.com/trusted-publishers/)
requires verified package/repository ownership. If npm cannot bootstrap a new
package through OIDC, that ownership problem must be resolved explicitly; adding
a long-lived npm token to this repository or workflow is not an acceptable
shortcut.

GitHub private vulnerability reporting, secret scanning with push protection,
a successful CodeQL run, and a named private security contact are also release
blockers. The supported-version table in `SECURITY.md` must be updated only
after a release is actually maintained.

**STOP — signed release authorization is unresolved.** The workflow still
requires the release tag to exist, peel to the checked-out commit, match the
package version, and point at a commit contained in `main`. It does not yet
verify a tag signature because the product has not recorded an exact allowed
signer fingerprint or a rotation/revocation policy. Do not create a release or
approve the `npm` environment until that trust decision exists and the workflow
has tested enforcement. Merely requiring an annotated or cryptographically
valid tag without checking the approved signer would not close this blocker.

## Artifact contract

The public `kavrix` archive is a dependency-free runtime package. Monorepo-only
`@kavrix/*` and esbuild entries are build inputs; the installed package resolves
no external runtime dependency. The deterministic ESM build emits `dist/bin.js`
as the only executable plus content-hashed `dist/chunks/chunk-*.js` modules.
Version and completion do not evaluate the lazy cryptography/key-file graph.
Inline source maps omit source contents, and compiled JavaScript embeds the
reviewed licenses for the four bundled npm libraries: Commander, Zod,
`libsodium-wrappers`, and `libsodium`.

The only public module export is `CLI_VERSION`, with a generated declaration
that has no private imports. The deterministic CycloneDX 1.6 SBOM binds the
complete JavaScript artifact set with one aggregate SHA-256 and a named SHA-256
for every entry/chunk/module. It records those four npm libraries and the EFF
Short Wordlist for Passphrases #1 as a distinct CC-BY-4.0 data component with
its authoritative source and reviewed pre-transformation source digest. The
installed README carries the matching attribution.

The public manifest pins `publishConfig.registry` to
`https://registry.npmjs.org/` and `publishConfig.access` to `public`. These are
defense-in-depth defaults; the authorized workflow still supplies the registry,
access, and provenance controls explicitly.

The current executable intentionally exposes only behavior backed by production
code: version/help, static completion, password/passphrase generation, TOTP, and
create-only portable key-file creation. Vault unlock, storage, sync, clipboard,
and network operations remain uncomposed and are not advertised by the packed
bin.

## Maintainer checklist

1. Start from a clean, reviewed commit on `main`; review changesets, the lockfile,
   build allowlist, dependency advisories, and every workflow change.
2. Set the stable or beta package version and matching CLI version, then run on
   Node 24.19.x:

   ```sh
   pnpm install --frozen-lockfile
   pnpm verify
   pnpm test:coverage
   pnpm audit --audit-level high
   pnpm --filter kavrix package:smoke
   ```

3. Require green Linux x64/arm64, macOS x64/arm64, and Windows x64
   verify/packed-install jobs, plus the pinned MongoDB replica-set transaction
   and plaintext-canary job. The workflow asserts `process.arch`; platform jobs
   prove only the OS/architecture they actually ran.
4. Resolve the signed-release-authorization STOP above. Only after the exact
   allowed signer and rotation/revocation policy are approved, implemented, and
   tested may maintainers create the signed version tag and matching GitHub
   release. A stable `X.Y.Z` version must use a non-prerelease release and
   publishes with the explicit `latest` npm dist-tag. A staged
   `X.Y.Z-beta.N` version must use a prerelease release and publishes with the
   explicit `beta` dist-tag; it can never update `latest`. In both cases the Git
   tag remains exactly `v<manifest version>`.
5. The release workflow fetches full history, peels the tag to its commit, proves
   that commit is contained in `origin/main`, and requires successful completed
   same-repository `main` push runs of both `.github/workflows/ci.yml` and
   `.github/workflows/codeql.yml` at that exact SHA. The exact-SHA CI run is the
   authoritative build, cross-platform, real-Mongo coverage, and package-smoke
   gate. A successful CodeQL workflow run is not sufficient by itself: the
   workflow also requires the named CodeQL analysis job and its analyze step to
   have completed successfully, not skipped. The release workflow therefore
   does not rerun the mismatched unit-only coverage topology. An unavailable or
   malformed GitHub Actions API response, either missing exact match, or a
   skipped analysis fails closed.
6. A validation job with no `id-token: write` installs dependencies, reruns
   verification, rejects token configuration, refreshes
   `pnpm audit --audit-level high`, and creates exactly one archive. The
   authoritative supplied-archive smoke installs that same archive offline and
   validates its dynamic chunk allowlist, README attribution,
   aggregate/per-artifact SBOM hashes, bundled-library licenses, EFF data
   component, canary absence, and lazy crypto loading. The job uploads only that
   named archive and exports its validated package version, npm dist-tag, and
   SHA-256.
7. A separate, protected `npm`-environment job is the only job granted
   `id-token: write`. It does not check out source, install dependencies, build,
   test, pack, or execute repository scripts. It downloads the single immutable
   validation artifact, requires exactly the expected filename and stable or
   beta version, recomputes and compares its SHA-256, revalidates its public
   manifest, and rejects token environment variables. It independently rechecks
   the version, GitHub prerelease flag, and `latest`/`beta` npm dist-tag tuple.
   It then passes that exact `.tgz`—not a rebuilt directory—to `npm publish`
   with `--ignore-scripts`, `--access public`, the validated explicit `--tag`,
   and `--provenance`. Authentication must come from npm OIDC, not `NPM_TOKEN`
   or `NODE_AUTH_TOKEN`.
8. After publication, verify registry provenance and signatures, install the
   exact published version on each supported platform, compare contents and
   behavior with the reviewed archive, and update the factual implementation and
   security-support documentation.

Do not tag, create a release, or publish from a dirty tree, a local tarball, an
unreviewed fork, or after any failed gate. “Prepared” and “published” are distinct
states.
