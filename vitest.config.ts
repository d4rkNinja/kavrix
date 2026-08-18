import { defineConfig } from 'vitest/config';

const testBoundaryTimeoutMs = process.platform === 'win32' ? 60_000 : 10_000;

export default defineConfig({
  test: {
    fileParallelism: process.platform !== 'win32',
    hookTimeout: testBoundaryTimeoutMs,
    include: [
      'apps/cli/test/local-vault-cli-view.test.ts',
      'apps/cli/test/local-secrets.test.ts',
      'apps/cli/test/package.test.ts',
      'packages/schemas/test/**/*.test.ts',
      'packages/crypto/test/**/*.test.ts',
      'packages/key-files/test/secure-stream.test.ts',
      'packages/key-files/test/recovery-kit-files.test.ts',
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
