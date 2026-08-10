import { defineConfig } from 'vitest/config';

const mongoIntegrationEnabled =
  process.env['KAVRIX_MONGODB_URI'] !== undefined &&
  process.env['KAVRIX_MONGODB_URI'].length > 0;

export default defineConfig({
  test: {
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
    testTimeout: 10_000,
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
