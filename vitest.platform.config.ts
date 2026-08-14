import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'scripts/platform-acceptance.test.ts',
      'packages/keychain/test/native-keychain.integration.test.ts',
      'packages/key-files/integration/**/*.integration.ts',
      'packages/clipboard/integration/**/*.integration.ts',
    ],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
    passWithNoTests: false,
    restoreMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,
  },
});
