# Releasing Kavrix

Releases are built from the public GitHub repository and published through npm's
OIDC trusted-publishing flow. No long-lived npm token belongs in GitHub secrets.

## One-time npm configuration

After the first `kavrix` package is created on npm:

1. Configure a GitHub trusted publisher for `d4rkNinja/kavrix`.
2. Set the workflow filename to `publish.yml` and environment to `npm`.
3. Allow publish (or staged publish when the registry workflow supports the
   project's approval policy).
4. Require 2FA and disallow traditional publish tokens.
5. Protect the `npm` GitHub environment and release tags with maintainer approval.

The repository and workflow fields are case-sensitive. npm requires the package's
`repository.url` to match the publishing repository. See the official
[trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/).

## Release checklist

1. Update implementation status and user-facing documentation.
2. Add and review changesets; run `pnpm version-packages` on the release branch.
3. Run `pnpm install --frozen-lockfile` and `pnpm verify` on a clean checkout.
4. Run `pnpm audit --audit-level high` and review all lockfile/install-script
   changes manually.
5. Build and inspect the public archive:

   ```sh
   pnpm --filter kavrix --fail-if-no-match pack --pack-destination package-artifacts
   pnpm --dir apps/cli pack --dry-run
   ```

6. Install that exact archive in clean Windows, macOS, and Linux environments and
   run CLI startup, unlock, crypto, key-file, keychain, clipboard, and TUI smoke
   tests. Do not claim an architecture that was not exercised.
7. Merge the version change, create a signed `vX.Y.Z` tag, and publish a GitHub
   release from that tag.
8. The release-triggered workflow reruns verification and publishes via OIDC. npm
   automatically attaches provenance for a public package built from a public
   repository through trusted publishing.
9. Verify package provenance/signatures with `npm audit signatures`, install the
   published version, and compare its behavior and contents with the reviewed
   archive.

Never publish directly from a dirty working tree or bypass a failed verification.
Release signing and platform archive checksums are added only after those artifact
formats have real cross-platform packaging tests.
