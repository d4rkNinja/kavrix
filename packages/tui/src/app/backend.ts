import type { AppScreenId } from './ids.js';

export type AppTone = 'info' | 'success' | 'warning' | 'error' | 'muted';

export interface AppProfileSummary {
  readonly id: string;
  readonly datastore: 'file' | 'mongodb';
  readonly selected: boolean;
  readonly vault?: string;
  readonly detail: string;
}

export interface AppVaultSummary {
  readonly id: string;
  readonly selected: boolean;
  readonly revision?: number;
  readonly credentialCount?: number;
  readonly detail: string;
}

export interface AppCredentialSummary {
  readonly name: string;
  readonly maskedValue: string;
  readonly updatedAt?: string;
}

export interface AppDoctorCheck {
  readonly name: string;
  readonly status: 'ok' | 'warning' | 'error';
  readonly detail: string;
}

export interface AppRecoverySlot {
  readonly slotId: string;
  readonly status: 'active' | 'revoked';
  readonly detail: string;
}

export interface AppPolicyRow {
  readonly id: string;
  readonly kind: 'policy' | 'grant' | 'audit';
  readonly summary: string;
}

export interface AppBrowseNode {
  readonly id: string;
  readonly kind: 'context' | 'service' | 'item' | 'field';
  readonly label: string;
  readonly detail: string;
}

export interface AppHomeStatus {
  readonly profileId: string | null;
  readonly vaultId: string | null;
  readonly unlocked: boolean;
  readonly credentialCount: number;
  readonly datastore: string | null;
  readonly message: string;
}

export interface AppSnapshot {
  readonly home: AppHomeStatus;
  readonly profiles: readonly AppProfileSummary[];
  readonly vaults: readonly AppVaultSummary[];
  readonly credentials: readonly AppCredentialSummary[];
  readonly doctor: readonly AppDoctorCheck[];
  readonly recovery: readonly AppRecoverySlot[];
  readonly policies: readonly AppPolicyRow[];
  readonly browse: readonly AppBrowseNode[];
  readonly runPreview: string;
  readonly agentStatus: string;
  readonly notice: string | null;
  readonly noticeTone: AppTone;
}

export type AppBackendAction =
  | Readonly<{ type: 'refresh' }>
  | Readonly<{ type: 'use-profile'; profileId: string }>
  | Readonly<{
      type: 'create-file-profile';
      profileId: string;
      dataFile: string;
      keyFile: string;
      passphrase: string;
      databaseLabel?: string;
      vaultLabel?: string;
    }>
  | Readonly<{ type: 'use-vault'; vaultId: string }>
  | Readonly<{ type: 'unlock'; passphrase: string }>
  | Readonly<{ type: 'lock' }>
  | Readonly<{ type: 'reveal-credential'; name: string }>
  | Readonly<{ type: 'put-credential'; name: string; value: string }>
  | Readonly<{ type: 'rename-credential'; from: string; to: string }>
  | Readonly<{ type: 'remove-credential'; name: string }>
  | Readonly<{ type: 'search-credentials'; query: string }>
  | Readonly<{ type: 'run-doctor' }>
  | Readonly<{ type: 'recovery-status' }>
  | Readonly<{
      type: 'recovery-create';
      recoveryFile: string;
      recoveryPassphrase: string;
    }>
  | Readonly<{
      type: 'recovery-verify';
      recoveryFile: string;
      recoveryPassphrase: string;
    }>
  | Readonly<{ type: 'recovery-revoke'; slotId: string }>
  | Readonly<{ type: 'preview-run'; credentialNames: readonly string[] }>
  | Readonly<{ type: 'agent-dry-run'; configPath?: string; agentName?: string }>
  | Readonly<{ type: 'refresh-policy' }>
  | Readonly<{
      type: 'policy-create';
      id: string;
      secret: string;
      command: string;
      env?: string;
    }>
  | Readonly<{ type: 'policy-remove'; id: string }>
  | Readonly<{
      type: 'grant-create';
      secret: string;
      command: string;
      ttl: string;
      env?: string;
      maxUses?: number;
    }>
  | Readonly<{ type: 'grant-revoke'; grantId: string }>
  | Readonly<{ type: 'refresh-browse' }>;

export type AppBackendResult = Readonly<{
  snapshot: AppSnapshot;
  /** Ephemeral revealed secret; never persisted in router state. */
  revealedSecret?: string;
}>;

/**
 * Host-owned use-case boundary. The TUI package never unlocks vaults or
 * touches secrets except through this port.
 */
export interface InteractiveAppBackend {
  load(): Promise<AppSnapshot>;
  dispatch(action: AppBackendAction): Promise<AppBackendResult>;
}

export function emptySnapshot(notice: string | null = null): AppSnapshot {
  return {
    home: {
      profileId: null,
      vaultId: null,
      unlocked: false,
      credentialCount: 0,
      datastore: null,
      message: 'No vault session yet.',
    },
    profiles: [],
    vaults: [],
    credentials: [],
    doctor: [],
    recovery: [],
    policies: [],
    browse: [],
    runPreview: 'Select credentials on the Run screen for a dry preview.',
    agentStatus: 'Agent broker idle (dry-run only from TUI).',
    notice,
    noticeTone: notice === null ? 'muted' : 'info',
  };
}

export function listScreenInventory(): readonly AppScreenId[] {
  return [
    'home',
    'profiles',
    'vaults',
    'credentials',
    'doctor',
    'recovery',
    'run',
    'policy',
    'agent',
    'browse',
    'help',
    'showcase',
  ];
}
