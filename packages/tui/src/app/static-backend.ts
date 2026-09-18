import {
  emptySnapshot,
  type AppBackendAction,
  type AppBackendResult,
  type AppSnapshot,
  type InteractiveAppBackend,
} from './backend.js';

/**
 * Read-only host backend that serves a fixed snapshot. Useful for CI inventory
 * smoke and presentational mounts that do not unlock vault material.
 */
export function createStaticAppBackend(
  initial: AppSnapshot = emptySnapshot('Static TUI snapshot.'),
): InteractiveAppBackend {
  let snapshot = initial;
  return {
    async load(): Promise<AppSnapshot> {
      return snapshot;
    },
    async dispatch(action: AppBackendAction): Promise<AppBackendResult> {
      switch (action.type) {
        case 'refresh':
        case 'run-doctor':
        case 'recovery-status':
        case 'refresh-policy':
        case 'refresh-browse':
        case 'agent-dry-run':
        case 'lock':
          snapshot = {
            ...snapshot,
            notice: `Handled ${action.type}.`,
            noticeTone: 'info',
          };
          return { snapshot };
        case 'search-credentials':
          snapshot = {
            ...snapshot,
            notice: `Search query recorded (${action.query.length} chars).`,
            noticeTone: 'info',
          };
          return { snapshot };
        case 'preview-run':
          snapshot = {
            ...snapshot,
            runPreview: `Dry preview for: ${action.credentialNames.join(', ') || '(none)'}`,
            notice: 'Run preview updated (no process spawned).',
            noticeTone: 'success',
          };
          return { snapshot };
        case 'reveal-credential':
          snapshot = {
            ...snapshot,
            notice: `REVEAL denied in static backend for ${action.name}.`,
            noticeTone: 'warning',
          };
          return { snapshot };
        case 'use-profile':
        case 'use-vault':
          snapshot = {
            ...snapshot,
            notice: `${action.type} requires the CLI-hosted vault backend.`,
            noticeTone: 'warning',
          };
          return { snapshot };
        case 'unlock': {
          const cleared = action.passphrase.length;
          snapshot = {
            ...snapshot,
            notice:
              cleared === 0
                ? 'Unlock requires a passphrase.'
                : 'Static backend cannot unlock a vault; use kavrix tui with a profile.',
            noticeTone: 'warning',
          };
          return { snapshot };
        }
      }
    },
  };
}
