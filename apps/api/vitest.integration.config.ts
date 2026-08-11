import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['apps/api/integration/**/*.integration.ts'],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 60_000,
    passWithNoTests: false,
    restoreMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,
  },
});
