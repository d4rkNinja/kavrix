import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/coverage/**', '**/dist/**', '**/node_modules/**', '**/*.d.ts'],
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
                '@kavrix/api',
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
    files: ['apps/api/src/**/*.{ts,tsx}', 'packages/storage/src/**/*.{ts,tsx}'],
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
