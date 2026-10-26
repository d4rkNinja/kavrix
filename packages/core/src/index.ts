export * from './secret-generator.js';

/**
 * Persistence ports owned by core. Adapters live in @kavrix/storage and
 * implement these interfaces; the port modules must depend only on
 * @kavrix/schemas (enforced by test/port-boundary.test.ts).
 */
export * from './ports/encrypted-vault-store.js';
export * from './ports/encrypted-database-store.js';
export * from './ports/collaborative-vault-store.js';
