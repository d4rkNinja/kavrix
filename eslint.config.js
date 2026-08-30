import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/coverage/**',
      '**/dist/**',
      '**/node_modules/**',
      '**/*.d.ts',
      'apps/cli/src/catalog.ts',
      'apps/cli/src/cli.ts',
      'apps/cli/src/contracts.ts',
      'apps/cli/src/errors.ts',
      'apps/cli/src/initialization.ts',
      'apps/cli/src/key-file-create.ts',
      'apps/cli/src/mutation-contracts.ts',
      'apps/cli/src/production/**',
      'apps/cli/src/public-security-tools.ts',
      'apps/cli/src/render.ts',
      'apps/cli/src/runtime-preflight.ts',
      'apps/cli/src/secret-input.ts',
      'apps/cli/src/session.ts',
      'apps/cli/src/terminal.ts',
      'apps/cli/test/**',
      'packages/client/**',
      'packages/sync/**',
      'packages/local-store/**',
      'packages/keychain/**',
      'packages/clipboard/**',
      'packages/import-export/**',
      'packages/storage/src/collections.ts',
      'packages/storage/src/documents.ts',
      'packages/storage/src/mongo-backup-source.ts',
      'packages/storage/src/mongo-backup-restore-store.ts',
      'packages/storage/src/mongo-document-preflight.ts',
      'packages/storage/src/mongo-validator-fragments.ts',
      'packages/storage/src/mongo-vault-storage.ts',
      'packages/storage/src/restore-documents.ts',
      'packages/storage/test/**',
      'packages/key-files/test/**',
      'packages/key-files/integration/**',
      'packages/storage/integration/**',
      'packages/storage/scripts/**',
      'packages/storage/vitest.integration.config.ts',
      'scripts/**',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/explicit-function-return-type': [
        'error',
        { allowExpressions: true },
      ],
      '@typescript-eslint/no-confusing-void-expression': 'error',
      '@typescript-eslint/no-deprecated': 'error',
      '@typescript-eslint/no-import-type-side-effects': 'error',
      '@typescript-eslint/no-unnecessary-condition': 'error',
      '@typescript-eslint/prefer-readonly': 'error',
      'no-warning-comments': [
        'error',
        { terms: ['fixme', 'hack', 'xxx'], location: 'anywhere' },
      ],
    },
  },
  {
    files: ['**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    files: ['packages/schemas/src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@kavrix/*'],
              message: 'Canonical schemas must not depend on another Kavrix package.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['packages/core/src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'commander', message: 'Core must not depend on the CLI parser.' },
            { name: 'fastify', message: 'Core must not depend on HTTP.' },
            { name: 'ink', message: 'Core must not depend on the TUI.' },
            { name: 'mongodb', message: 'Core must not depend on persistence.' },
            { name: 'react', message: 'Core must not depend on the TUI.' },
          ],
          patterns: [
            {
              group: [
                '@kavrix/client',
                '@kavrix/clipboard',
                '@kavrix/crypto',
                '@kavrix/import-export',
                '@kavrix/key-files',
                '@kavrix/keychain',
                '@kavrix/local-store',
                '@kavrix/runner',
                '@kavrix/storage',
                '@kavrix/sync',
                '@kavrix/tui',
              ],
              message: 'Core may expose ports but must not import outer adapters.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['packages/storage/src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                '@kavrix/client',
                '@kavrix/clipboard',
                '@kavrix/crypto',
                '@kavrix/import-export',
                '@kavrix/key-files',
                '@kavrix/keychain',
                '@kavrix/local-store',
                '@kavrix/runner',
                '@kavrix/tui',
              ],
              message:
                'The zero-knowledge server/storage graph must not import client-side secret capabilities.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['packages/sync/src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                '@kavrix/client',
                '@kavrix/core',
                '@kavrix/crypto',
                '@kavrix/keychain',
                '@kavrix/storage',
              ],
              message:
                'Sync must remain an opaque transport/state engine with schema-only records.',
            },
          ],
        },
      ],
    },
  },
);
