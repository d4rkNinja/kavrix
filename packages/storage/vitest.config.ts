import { defineConfig } from 'vitest/config';

const testBoundaryTimeoutMs = process.platform === 'win32' ? 60_000 : 10_000;

export default defineConfig({
  test: {
    fileParallelism: process.platform !== 'win32',
    include: [
      'packages/storage/test/**/*.test.ts',
      'packages/storage/test/**/*.integration.test.ts',
    ],
    passWithNoTests: false,
    restoreMocks: true,
    testTimeout: testBoundaryTimeoutMs,
  },
});
