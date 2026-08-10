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

The current executable intentionally exposes only behavior backed by production
code: version/help, static completion, password/passphrase generation, TOTP, and
create-only portable key-file creation. Vault unlock, storage, sync, clipboard,
and network operations remain uncomposed and are not advertised by the packed
bin.

## Maintainer checklist

1. Start from a clean, reviewed commit on `main`; review changesets, the lockfile,
   build allowlist, dependency advisories, and every workflow change.
2. Set the stable package version and matching CLI version, then run on Node
   24.19.x:

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
4. Create a signed `vX.Y.Z` tag at that exact commit and a non-prerelease GitHub
   release only after publication has been authorized.
5. The release workflow checks out the tag, proves `vX.Y.Z` equals the package
   version, rejects token configuration, reruns verification, and creates exactly
   one archive. The authoritative supplied-archive smoke installs that same
   archive offline and validates its dynamic chunk allowlist, README attribution,
   aggregate/per-artifact SBOM hashes, bundled-library licenses, EFF data
   component, canary absence, and lazy crypto loading. No later step rebuilds or
   repacks it before it is uploaded as the immutable workflow artifact.
6. The workflow passes that exact `.tgz`—not a rebuilt directory—to
   `npm publish --access public --provenance`. Authentication must come from npm
   OIDC (`id-token: write`), not `NPM_TOKEN` or `NODE_AUTH_TOKEN`.
7. After publication, verify registry provenance and signatures, install the
   exact published version on each supported platform, compare contents and
   behavior with the reviewed archive, and update the factual implementation and
   security-support documentation.

Do not tag, create a release, or publish from a dirty tree, a local tarball, an
unreviewed fork, or after any failed gate. “Prepared” and “published” are distinct
states.
