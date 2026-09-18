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
        case 'agent-dry-run':
        case 'lock':
          snapshot = {
            ...snapshot,
            notice: `Handled ${action.type}.`,
            noticeTone: 'info',
          };
          return { snapshot };
        case 'refresh-browse':
          snapshot = {
            ...snapshot,
            browse:
              snapshot.browse.length > 0
                ? snapshot.browse
                : [
                    {
                      id: 'static-context',
                      kind: 'context' as const,
                      label: 'static',
                      detail: 'Static browse placeholder (CLI backend loads real lists).',
                    },
                  ],
            notice: 'Browse refreshed (static).',
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
            runPreview: `Validated names (static): ${action.credentialNames.join(', ') || '(none)'}. run --help not spawned in static backend.`,
            notice: 'Run preview validated against static credential list.',
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
        case 'copy-credential':
          snapshot = {
            ...snapshot,
            notice: `Copied (clipboard clears in ~30s) — static stub for ${action.name}.`,
            noticeTone: 'success',
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

        case 'recovery-create': {
          const slotId = `slot-${String(snapshot.recovery.length + 1)}`;
          snapshot = {
            ...snapshot,
            recovery: [
              ...snapshot.recovery.filter((slot) => slot.slotId !== '(none)'),
              {
                slotId,
                status: 'active',
                detail: `Created (static) at ${action.recoveryFile}`,
              },
            ],
            notice: `Created recovery kit (static) ${slotId}.`,
            noticeTone: 'success',
          };
          return { snapshot };
        }
        case 'recovery-verify':
          snapshot = {
            ...snapshot,
            notice: `Verified recovery kit (static) ${action.recoveryFile}.`,
            noticeTone: 'success',
          };
          return { snapshot };
        case 'recovery-revoke': {
          const active = snapshot.recovery.filter((slot) => slot.status === 'active');
          if (active.length <= 1) {
            snapshot = {
              ...snapshot,
              notice: 'Cannot revoke the last active recovery slot.',
              noticeTone: 'error',
            };
            return { snapshot };
          }
          snapshot = {
            ...snapshot,
            recovery: snapshot.recovery.map((slot) =>
              slot.slotId === action.slotId
                ? { ...slot, status: 'revoked' as const, detail: 'Revoked (static).' }
                : slot,
            ),
            notice: `Revoked recovery slot ${action.slotId} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };
        }
        case 'policy-create': {
          const rows = snapshot.policies.filter((row) => row.id !== action.id && row.id !== '(none)');
          snapshot = {
            ...snapshot,
            policies: [
              ...rows,
              {
                id: action.id,
                kind: 'policy' as const,
                summary: `secret=${action.secret} cmds=${action.command}`,
              },
            ],
            notice: `Created policy ${action.id} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };
        }
        case 'policy-remove':
          snapshot = {
            ...snapshot,
            policies: snapshot.policies.filter((row) => row.id !== action.id),
            notice: `Removed policy ${action.id} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };
        case 'grant-create': {
          const grantId = `grant_static_${String(snapshot.policies.length + 1)}`;
          snapshot = {
            ...snapshot,
            policies: [
              ...snapshot.policies.filter((row) => row.id !== '(none)'),
              {
                id: grantId,
                kind: 'grant' as const,
                summary: `secret=${action.secret} status=active ttl=${action.ttl}`,
              },
            ],
            notice: `Created grant ${grantId} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };
        }
        case 'grant-revoke':
          snapshot = {
            ...snapshot,
            policies: snapshot.policies.filter((row) => row.id !== action.grantId),
            notice: `Revoked grant ${action.grantId} (static).`,
            noticeTone: 'success',
          };
          return { snapshot };

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
        case 'create-mongodb-profile': {
          const profileId = action.profileId.trim();
          if (
            profileId.length === 0 ||
            action.passphrase.length === 0 ||
            action.databaseUrl.trim().length === 0
          ) {
            snapshot = {
              ...snapshot,
              notice:
                'create-mongodb-profile requires profile id, database URL, and passphrase.',
              noticeTone: 'warning',
            };
            return { snapshot };
          }
          const profiles = [
            ...snapshot.profiles.map((profile) => ({ ...profile, selected: false })),
            {
              id: profileId,
              datastore: 'mongodb' as const,
              selected: true,
              detail: `mongodb ${action.database}`,
            },
          ];
          snapshot = {
            ...snapshot,
            profiles,
            home: {
              ...snapshot.home,
              profileId,
              vaultId: `${profileId}-vault`,
              datastore: 'mongodb',
              unlocked: false,
              credentialCount: 0,
              message: `Created mongodb profile ${profileId} (static).`,
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
            notice: `Created mongodb profile ${profileId} (static).`,
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
