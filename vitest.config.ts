import { defineConfig } from 'vitest/config';

const mongoIntegrationEnabled =
  process.env['KAVRIX_MONGODB_URI'] !== undefined &&
  process.env['KAVRIX_MONGODB_URI'].length > 0;
const testBoundaryTimeoutMs = process.platform === 'win32' ? 60_000 : 10_000;

export default defineConfig({
  test: {
    // Windows security tests intentionally exercise real PowerShell, ACL, and
    // process boundaries. Running those files concurrently can starve the
    // fixed fail-closed helper timeouts on two-core CI runners.
    fileParallelism: process.platform !== 'win32',
    hookTimeout: testBoundaryTimeoutMs,
    include: mongoIntegrationEnabled
      ? [
          '{apps,packages}/**/*.test.ts',
          'apps/api/integration/**/*.integration.ts',
          'packages/storage/integration/**/*.integration.ts',
        ]
      : ['{apps,packages}/**/*.test.ts'],
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
