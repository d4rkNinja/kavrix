import { defineConfig } from 'vitest/config';

// Windows security tests invoke the platform ACL verifier repeatedly across
// multi-step database workflows. Keep the fail-closed checks real while giving
// the slower process boundary enough time on hosted and local Windows runners.
const testBoundaryTimeoutMs = process.platform === 'win32' ? 360_000 : 10_000;

export default defineConfig({
  test: {
    fileParallelism: process.platform !== 'win32',
    hookTimeout: testBoundaryTimeoutMs,
    include: [
      'apps/cli/test/database-session.test.ts',
      'apps/cli/test/database-commands.test.ts',
      'apps/cli/test/database-flat-commands.test.ts',
      'apps/cli/test/database-migration.test.ts',
      'apps/cli/test/datastore-profile-publication.test.ts',
      'apps/cli/test/datastore-profiles.test.ts',
      'apps/cli/test/local-vault-cli-view.test.ts',
      'apps/cli/test/local-secrets.test.ts',
      'apps/cli/test/package.test.ts',
      'packages/schemas/test/database-container.test.ts',
      'packages/schemas/test/**/*.test.ts',
      'packages/crypto/test/**/*.test.ts',
      'packages/key-files/test/secure-stream.test.ts',
      'packages/key-files/test/canonical-json-document.test.ts',
      'packages/key-files/test/canonical-json-document-failure.test.ts',
      'packages/key-files/test/recovery-kit-files.test.ts',
      'packages/key-files/test/database-key-files.test.ts',
      'packages/key-files/test/database-recovery-kit-files.test.ts',
      'packages/key-files/test/database-revision-anchor.test.ts',
      'packages/key-files/test/database-owned-publication.test.ts',
      'packages/storage/test/file-local-vault.test.ts',
      'packages/storage/test/file-encrypted-database.test.ts',
      'packages/storage/test/encrypted-database-store-contract.test.ts',
      'packages/storage/test/mongo-encrypted-database.test.ts',
      'packages/storage/test/mongo-encrypted-database.integration.test.ts',
      'packages/storage/test/mongo-local-vault-uri.test.ts',
    ],
    passWithNoTests: false,
    restoreMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,
    testTimeout: testBoundaryTimeoutMs,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      include: ['{apps,packages}/**/src/**/*.{ts,tsx}'],
      exclude: ['**/src/index.ts'],
      thresholds: {
        branches: 80,
        functions: 85,
        lines: 85,
        statements: 85,
      },
    },
  },
});
