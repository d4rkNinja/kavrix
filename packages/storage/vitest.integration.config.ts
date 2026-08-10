import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/storage/integration/**/*.integration.ts'],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 60_000,
    restoreMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,
  },
});
