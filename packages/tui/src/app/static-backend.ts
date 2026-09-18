import {
  emptySnapshot,
  type AppBackendAction,
  type AppBackendResult,
  type AppCredentialSummary,
  type AppSnapshot,
  type InteractiveAppBackend,
} from './backend.js';

/**
 * Read-only host backend that serves a fixed snapshot. Useful for CI inventory
 * smoke and presentational mounts that do not unlock vault material.
 * Credential put/rename/remove mutate the in-memory snapshot only.
 */
export function createStaticAppBackend(
  initial: AppSnapshot = emptySnapshot('Static TUI snapshot.'),
): InteractiveAppBackend {
  let snapshot = initial;
  const asciiMask = (): string =>
    snapshot.credentials[0]?.maskedValue.includes('•') === true ? '••••••••' : '********';

  return {
    async load(): Promise<AppSnapshot> {
      return snapshot;
    },
    async dispatch(action: AppBackendAction): Promise<AppBackendResult> {
      switch (action.type) {
        case 'refresh':
        case 'run-doctor':
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
        case 'recovery-status':
          snapshot = {
            ...snapshot,
            recovery:
              snapshot.recovery.length > 0
                ? snapshot.recovery
                : [
                    {
                      slotId: '(none)',
                      status: 'active',
                      detail: 'Static recovery status (no kits).',
                    },
                  ],
            notice: 'Recovery status refreshed (static).',
            noticeTone: 'info',
          };
          return { snapshot };
        case 'search-credentials': {
          const query = action.query.trim().toLocaleLowerCase();
          const filtered =
            query.length === 0
              ? snapshot.credentials
              : snapshot.credentials.filter((credential) =>
                  credential.name.toLocaleLowerCase().includes(query),
                );
          snapshot = {
            ...snapshot,
            credentials: filtered,
            home: {
              ...snapshot.home,
              credentialCount: filtered.length,
            },
            notice: `Search query recorded (${action.query.length} chars).`,
            noticeTone: 'info',
          };
          return { snapshot };
        }
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
        case 'put-credential': {
          const name = action.name.trim();
          if (name.length === 0 || action.value.length === 0) {
            snapshot = {
              ...snapshot,
              notice: 'put-credential requires a non-empty name and value.',
              noticeTone: 'warning',
            };
            return { snapshot };
          }
          const mask = asciiMask();
          const next: AppCredentialSummary = { name, maskedValue: mask };
          const without = snapshot.credentials.filter((credential) => credential.name !== name);
          const credentials = [...without, next].sort((left, right) =>
            left.name.localeCompare(right.name),
          );
          snapshot = {
            ...snapshot,
            credentials,
            home: {
              ...snapshot.home,
              credentialCount: credentials.length,
              unlocked: true,
            },
            notice: `Stored credential ${name} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };
        }
        case 'rename-credential': {
          const from = action.from.trim();
          const to = action.to.trim();
          if (from.length === 0 || to.length === 0) {
            snapshot = {
              ...snapshot,
              notice: 'rename-credential requires from and to names.',
              noticeTone: 'warning',
            };
            return { snapshot };
          }
          if (snapshot.credentials.every((credential) => credential.name !== from)) {
            snapshot = {
              ...snapshot,
              notice: `Credential ${from} not found (static).`,
              noticeTone: 'error',
            };
            return { snapshot };
          }
          if (snapshot.credentials.some((credential) => credential.name === to)) {
            snapshot = {
              ...snapshot,
              notice: `Credential ${to} already exists (static).`,
              noticeTone: 'error',
            };
            return { snapshot };
          }
          const credentials = snapshot.credentials.map((credential) =>
            credential.name === from ? { ...credential, name: to } : credential,
          );
          snapshot = {
            ...snapshot,
            credentials,
            notice: `Renamed ${from} → ${to} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };
        }
        case 'remove-credential': {
          const name = action.name.trim();
          if (name.length === 0) {
            snapshot = {
              ...snapshot,
              notice: 'remove-credential requires a name.',
              noticeTone: 'warning',
            };
            return { snapshot };
          }
          const credentials = snapshot.credentials.filter(
            (credential) => credential.name !== name,
          );
          if (credentials.length === snapshot.credentials.length) {
            snapshot = {
              ...snapshot,
              notice: `Credential ${name} not found (static).`,
              noticeTone: 'error',
            };
            return { snapshot };
          }
          snapshot = {
            ...snapshot,
            credentials,
            home: {
              ...snapshot.home,
              credentialCount: credentials.length,
            },
            notice: `Removed credential ${name} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };
        }
        case 'create-file-profile': {
          const profileId = action.profileId.trim();
          if (profileId.length === 0 || action.passphrase.length === 0) {
            snapshot = {
              ...snapshot,
              notice: 'create-file-profile requires profile id and passphrase.',
              noticeTone: 'warning',
            };
            return { snapshot };
          }
          const profiles = [
            ...snapshot.profiles.map((profile) => ({ ...profile, selected: false })),
            {
              id: profileId,
              datastore: 'file' as const,
              selected: true,
              detail: `file ${action.dataFile}`,
            },
          ];
          snapshot = {
            ...snapshot,
            profiles,
            home: {
              ...snapshot.home,
              profileId,
              vaultId: `${profileId}-vault`,
              datastore: 'file',
              unlocked: false,
              credentialCount: 0,
              message: `Created file profile ${profileId} (static).`,
            },
            vaults: [
              {
                id: `${profileId}-vault`,
                selected: true,
                credentialCount: 0,
                detail: 'Created (static) — unlock to load credentials',
              },
            ],
            credentials: [],
            notice: `Created file profile ${profileId} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };
        }
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
