import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { lstat, realpath } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { zeroize } from '@kavrix/crypto';
import {
  ensureSecureDirectory,
  hardenExistingSecureDirectory,
} from '@kavrix/key-files';
import { profileIdSchema } from '@kavrix/schemas';

import {
  DatastoreProfileRegistry,
  type DatastoreProfile,
} from './datastore-profiles.js';
import { getKavrixConfigDir } from './kavrix-config.js';
import { copySecretToClipboard } from './tui-clipboard.js';

/**
 * Structural host backend used by `kavrix tui`. Kept free of `@kavrix/tui`
 * runtime imports so the CLI bundle does not pull Ink into every command.
 */
export interface CliTuiSnapshot {
  readonly home: {
    readonly profileId: string | null;
    readonly vaultId: string | null;
    readonly unlocked: boolean;
    readonly credentialCount: number;
    readonly datastore: string | null;
    readonly message: string;
  };
  readonly profiles: readonly Readonly<{
    id: string;
    datastore: 'file' | 'mongodb';
    selected: boolean;
    vault?: string;
    detail: string;
  }>[];
  readonly vaults: readonly Readonly<{
    id: string;
    selected: boolean;
    revision?: number;
    credentialCount?: number;
    detail: string;
  }>[];
  readonly credentials: readonly Readonly<{
    name: string;
    maskedValue: string;
    updatedAt?: string;
  }>[];
  readonly doctor: readonly Readonly<{
    name: string;
    status: 'ok' | 'warning' | 'error';
    detail: string;
  }>[];
  readonly recovery: readonly Readonly<{
    slotId: string;
    status: 'active' | 'revoked';
    detail: string;
  }>[];
  readonly policies: readonly Readonly<{
    id: string;
    kind: 'policy' | 'grant' | 'audit';
    summary: string;
    status?: 'active' | 'expired' | 'exhausted' | 'revoked' | 'clock-invalid';
  }>[];
  readonly browse: readonly Readonly<{
    id: string;
    kind: 'context' | 'service' | 'item' | 'field';
    label: string;
    detail: string;
  }>[];
  readonly runPreview: string;
  readonly agentStatus: string;
  readonly notice: string | null;
  readonly noticeTone: 'info' | 'success' | 'warning' | 'error' | 'muted';
}

export type CliTuiAction =
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
      /** When set (init onboarding), create + verify a recovery kit after vault. */
      recoveryFile?: string;
      recoveryPassphrase?: string;
    }>
  | Readonly<{
      type: 'create-mongodb-profile';
      profileId: string;
      database: string;
      keyFile: string;
      databaseUrl: string;
      passphrase: string;
      databaseLabel?: string;
      vaultLabel?: string;
      databaseCollection?: string;
      vaultCollection?: string;
      /** When set (init onboarding), create + verify a recovery kit after vault. */
      recoveryFile?: string;
      recoveryPassphrase?: string;
    }>
  | Readonly<{ type: 'use-vault'; vaultId: string }>
  | Readonly<{ type: 'create-vault'; label: string }>
  | Readonly<{ type: 'remove-profile'; profileId: string }>
  | Readonly<{
      type: 'unlock';
      passphrase: string;
      databaseUrl?: string;
    }>
  | Readonly<{ type: 'lock' }>
  | Readonly<{ type: 'reveal-credential'; name: string }>
  | Readonly<{ type: 'copy-credential'; name: string }>
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

export interface CliTuiBackend {
  load(): Promise<CliTuiSnapshot>;
  dispatch(
    action: CliTuiAction,
  ): Promise<Readonly<{ snapshot: CliTuiSnapshot; revealedSecret?: string }>>;
}

export type CliTuiCommandRunner = (
  args: readonly string[],
  frames: readonly string[],
) => Promise<string>;

const require = createRequire(import.meta.url);

export interface CliTuiSessionOptions {
  readonly profileConfigDir?: string;
  readonly ascii?: boolean;
  binPath?: string;
  /** Optional injectable CLI runner (tests); secrets stay in frames only. */
  readonly commandRunner?: CliTuiCommandRunner;
  /** Injectable kavrix artifact home (~/.kavrix) for tests; defaults to homedir. */
  readonly kavrixArtifactDir?: string;
}

/**
 * Portable-key / vault / recovery writes require an existing owner-only parent.
 * Classic guided init ensures `~/.kavrix`; TUI create must do the same for
 * default and operator-chosen paths so empty HOME does not fail with
 * KEY_FILE_NOT_FOUND during db init / recovery.
 */
async function ensureSecureArtifactParents(
  paths: readonly (string | undefined | null)[],
  kavrixArtifactDir?: string,
): Promise<void> {
  const kavrixBase = kavrixArtifactDir ?? getKavrixConfigDir();
  const seen = new Set<string>();
  for (const candidate of paths) {
    if (typeof candidate !== 'string') continue;
    const trimmed = candidate.trim();
    if (trimmed.length === 0) continue;
    const parent = dirname(trimmed);
    if (parent.length === 0 || seen.has(parent)) continue;
    seen.add(parent);
    try {
      const metadata = await lstat(parent);
      if (!metadata.isDirectory()) {
        throw new Error(`Artifact parent is not a directory: ${parent}`);
      }
      // Parent already exists (e.g. secure test scratch under /tmp). Do not call
      // ensureSecureDirectory — that re-validates the grandparent and fails when
      // the grandparent is a world-writable temp root. Exception: the kavrix
      // artifact home is kavrix-owned state, so an existing directory that
      // predates strict ACLs (0.2.x upgrades inherit profile-directory ACEs on
      // Windows) is hardened here — idempotent when already strict.
      if (await isSameDirectoryPath(parent, kavrixBase)) {
        await hardenExistingSecureDirectory(parent);
      }
    } catch (error) {
      const code =
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        typeof error.code === 'string'
          ? error.code
          : undefined;
      if (code !== 'ENOENT') throw error;
      await ensureSecureDirectory(parent);
    }
  }
}

async function isSameDirectoryPath(left: string, right: string): Promise<boolean> {
  try {
    return (await realpath(left)) === (await realpath(right));
  } catch {
    return false;
  }
}

export function createCliTuiBackend(options: CliTuiSessionOptions = {}): CliTuiBackend {
  const session = new CliTuiSession(options);
  return {
    load: () => session.snapshot(),
    dispatch: (action) => session.dispatch(action),
  };
}

class CliTuiSession {
  readonly #options: CliTuiSessionOptions;
  #passphrase: Buffer | null = null;
  #credentialNames: string[] = [];
  #vaultId: string | null = null;
  #recoverySlots: CliTuiSnapshot['recovery'] = [];
  #doctorRows: CliTuiSnapshot['doctor'] = [];
  #policyRows: CliTuiSnapshot['policies'] = [];
  #runPreview: string | null = null;
  #agentStatus: string | null = null;
  #browseNodes: CliTuiSnapshot['browse'] = [];
  #databaseUrl: Buffer | null = null;
  #notice: string | null = 'Loaded profile registry.';
  #noticeTone: CliTuiSnapshot['noticeTone'] = 'info';

  constructor(options: CliTuiSessionOptions) {
    this.#options = options;
  }

  async snapshot(): Promise<CliTuiSnapshot> {
    return this.#buildSnapshot();
  }

  async dispatch(
    action: CliTuiAction,
  ): Promise<Readonly<{ snapshot: CliTuiSnapshot; revealedSecret?: string }>> {
    try {
      switch (action.type) {
        case 'refresh':
          if (this.#passphrase !== null) {
            await this.#refreshCredentialList();
          }
          this.#notice = 'Refreshed.';
          this.#noticeTone = 'info';
          break;
        case 'use-profile':
          await this.#useProfile(action.profileId);
          break;
        case 'create-file-profile':
          await this.#createFileProfile(action);
          break;
        case 'create-mongodb-profile':
          await this.#createMongodbProfile(action);
          break;
        case 'use-vault':
          await this.#useVault(action.vaultId);
          break;
        case 'create-vault':
          await this.#createVault(action.label);
          break;
        case 'remove-profile':
          await this.#removeProfile(action.profileId);
          break;
        case 'unlock':
          await this.#unlock(action.passphrase, action.databaseUrl);
          break;
        case 'lock':
          this.#lock();
          this.#notice = 'Session locked; secrets cleared.';
          this.#noticeTone = 'success';
          break;
        case 'reveal-credential': {
          const revealed = await this.#reveal(action.name);
          const snapshot = await this.#buildSnapshot();
          return { snapshot, revealedSecret: revealed };
        }
        case 'copy-credential':
          await this.#copyCredential(action.name);
          break;
        case 'put-credential':
          await this.#putCredential(action.name, action.value);
          break;
        case 'rename-credential':
          await this.#renameCredential(action.from, action.to);
          break;
        case 'remove-credential':
          await this.#removeCredential(action.name);
          break;
        case 'search-credentials': {
          const query = action.query.trim().toLocaleLowerCase();
          this.#credentialNames = this.#credentialNames.filter((name) =>
            name.toLocaleLowerCase().includes(query),
          );
          this.#notice = `Filtered credentials (${String(this.#credentialNames.length)}).`;
          this.#noticeTone = 'info';
          break;
        }
        case 'run-doctor':
          await this.#runDoctor();
          break;
        case 'recovery-status':
          await this.#recoveryStatus();
          break;
        case 'recovery-create':
          await this.#recoveryCreate(action.recoveryFile, action.recoveryPassphrase);
          break;
        case 'recovery-verify':
          await this.#recoveryVerify(action.recoveryFile, action.recoveryPassphrase);
          break;
        case 'recovery-revoke':
          await this.#recoveryRevoke(action.slotId);
          break;
        case 'preview-run':
          await this.#previewRun(action.credentialNames);
          break;
        case 'agent-dry-run':
          await this.#agentDryRun(action.configPath, action.agentName);
          break;
        case 'refresh-policy':
          await this.#refreshPolicy();
          break;
        case 'policy-create':
          await this.#policyCreate(action);
          break;
        case 'policy-remove':
          await this.#policyRemove(action.id);
          break;
        case 'grant-create':
          await this.#grantCreate(action);
          break;
        case 'grant-revoke':
          await this.#grantRevoke(action.grantId);
          break;
        case 'refresh-browse':
          await this.#refreshBrowse();
          break;
      }
      return { snapshot: await this.#buildSnapshot() };
    } catch (error) {
      this.#notice =
        error instanceof Error ? error.message : 'Operation failed safely.';
      this.#noticeTone = 'error';
      return { snapshot: await this.#buildSnapshot() };
    }
  }

  async #buildSnapshot(): Promise<CliTuiSnapshot> {
    const registry = await DatastoreProfileRegistry.openIfPresent({
      ...(this.#options.profileConfigDir === undefined
        ? {}
        : { configDirectory: this.#options.profileConfigDir }),
    });
    const profiles = registry === null ? [] : await registry.list();
    const current = registry === null ? null : await registry.current();
    const ascii = this.#options.ascii === true;
    const mask = ascii ? '********' : '••••••••';
    const recovery =
      this.#recoverySlots.length > 0
        ? this.#recoverySlots
        : [
            {
              slotId: '(see CLI)',
              status: 'active' as const,
              detail:
                'Open Recovery kit for key-material slots. Doctor / heal repairs local state — it is not recovery-kit use.',
            },
          ];
    return {
      home: {
        profileId: current?.id ?? null,
        vaultId: this.#vaultId ?? current?.defaultVaultId ?? null,
        unlocked: this.#passphrase !== null,
        credentialCount: this.#credentialNames.length,
        datastore: current?.datastore ?? null,
        message:
          current === null
            ? 'No profile selected. Add one with kavrix db profile / init.'
            : `Using profile ${current.id} (${current.datastore}).`,
      },
      profiles: profiles.map((profile) => ({
        id: profile.id,
        datastore: profile.datastore,
        selected: current?.id === profile.id,
        ...(profile.defaultVaultId === undefined
          ? {}
          : { vault: profile.defaultVaultId }),
        detail: describeProfile(profile),
      })),
      vaults:
        this.#vaultId === null && current?.defaultVaultId === undefined
          ? []
          : [
              {
                id: this.#vaultId ?? current?.defaultVaultId ?? 'default',
                selected: true,
                credentialCount: this.#credentialNames.length,
                detail: this.#passphrase
                  ? `${String(this.#credentialNames.length)} credentials loaded`
                  : 'Locked — press u to unlock',
              },
            ],
      credentials: this.#credentialNames.map((name) => ({
        name,
        maskedValue: mask,
      })),
      doctor:
        this.#doctorRows.length > 0
          ? this.#doctorRows
          : this.#passphrase === null
            ? [
                {
                  name: 'session',
                  status: 'warning' as const,
                  detail: 'Unlock to run authenticated doctor checks.',
                },
              ]
            : [
                {
                  name: 'session',
                  status: 'ok' as const,
                  detail: `Unlocked with ${String(this.#credentialNames.length)} credentials.`,
                },
              ],
      recovery,
      policies:
        this.#policyRows.length > 0
          ? this.#policyRows
          : [
              {
                id: '(none)',
                kind: 'audit' as const,
                summary: 'Press Enter to load policy/grant/audit via CLI.',
              },
            ],
      browse:
        this.#browseNodes.length > 0
          ? this.#browseNodes
          : [
              {
                id: 'root',
                kind: 'context' as const,
                label: current?.id ?? '(none)',
                detail:
                  this.#passphrase === null
                    ? 'Unlock to load kavrix context / service / item lists.'
                    : 'Press Enter to refresh browse from CLI.',
              },
            ],
      runPreview:
        this.#runPreview ??
        (this.#credentialNames.length === 0
          ? 'Unlock and press p to validate a run preview via CLI.'
          : `Available: ${this.#credentialNames.slice(0, 8).join(', ')}`),
      agentStatus: this.#agentStatus ?? '',
      notice: this.#notice,
      noticeTone: this.#noticeTone,
    };
  }

  async #useProfile(profileId: string): Promise<void> {
    const registry = await DatastoreProfileRegistry.open({
      ...(this.#options.profileConfigDir === undefined
        ? {}
        : { configDirectory: this.#options.profileConfigDir }),
    });
    await registry.use(profileIdSchema.parse(profileId));
    this.#lock();
    // Drop any vault override from the previous profile — browse/recovery must
    // not keep sending --vault <foreign-id> after a profile switch.
    this.#vaultId = null;
    this.#recoverySlots = [];
    this.#doctorRows = [];
    this.#policyRows = [];
    this.#runPreview = null;
    this.#agentStatus = null;
    this.#browseNodes = [];
    this.#clearDatabaseUrl();
    this.#notice = `Selected profile ${profileId}.`;
    this.#noticeTone = 'success';
  }

  /**
   * Select a vault via real `kavrix db vault use` (passphrase on stdin frames).
   * Updates the session override only after the CLI succeeds.
   */
  async #useVault(vaultId: string): Promise<void> {
    const id = vaultId.trim();
    if (id.length === 0) {
      throw new Error('Vault id required.');
    }
    if (this.#passphrase === null) {
      throw new Error('Unlock before selecting a vault.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const frames = await this.#ownerAuthFrames([passphrase]);
    const transport = await this.#ownerTransportArgs();
    await this.#runTextCommand(
      [
        'db',
        'vault',
        'use',
        id,
        ...(await this.#profileArgs()),
        ...transport,
        '--passphrase-stdin',
      ],
      frames,
    );
    this.#vaultId = id;
    this.#browseNodes = [];
    this.#notice = `Selected vault ${id}.`;
    this.#noticeTone = 'success';
  }

  async #createVault(label: string): Promise<void> {
    const vaultLabel = label.trim();
    if (vaultLabel.length === 0) {
      throw new Error('Vault label required.');
    }
    if (this.#passphrase === null) {
      throw new Error('Unlock before creating a vault.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const frames = await this.#ownerAuthFrames([passphrase, vaultLabel]);
    const transport = await this.#ownerTransportArgs();
    const created = await this.#runJsonCommand(
      [
        'db',
        'vault',
        'create',
        ...(await this.#profileArgs()),
        ...transport,
        '--passphrase-stdin',
        '--json',
      ],
      frames,
    );
    const vaultId =
      typeof created === 'object' &&
      created !== null &&
      typeof (created as { vaultId?: unknown }).vaultId === 'string'
        ? (created as { vaultId: string }).vaultId
        : null;
    if (vaultId === null) {
      throw new Error('db vault create did not return a vaultId.');
    }
    await this.#useVault(vaultId);
    this.#vaultId = vaultId;
    this.#notice = `Created vault ${vaultId} (${vaultLabel}).`;
    this.#noticeTone = 'success';
  }

  async #removeProfile(profileId: string): Promise<void> {
    const id = profileId.trim();
    if (id.length === 0) {
      throw new Error('Profile id required.');
    }
    const current = await this.#currentProfile();
    await this.#runJsonCommand(
      [
        'db',
        'profile',
        'remove',
        id,
        ...(this.#options.profileConfigDir === undefined
          ? []
          : ['--profile-config-dir', this.#options.profileConfigDir]),
        '--json',
      ],
      [],
    );
    if (current?.id === id) {
      // Removing the selected profile ends its session: selection cleared on
      // disk, so drop the in-memory unlock material and derived rows too.
      this.#lock();
      this.#vaultId = null;
      this.#recoverySlots = [];
      this.#doctorRows = [];
      this.#policyRows = [];
      this.#runPreview = null;
      this.#agentStatus = null;
      this.#browseNodes = [];
      this.#credentialNames = [];
      this.#clearDatabaseUrl();
    }
    this.#notice = `Removed profile ${id}.`;
    this.#noticeTone = 'success';
  }

  /**
   * Matches scripts/tui-vault-smoke.ts:
   * db profile add → db profile use → db init → db vault create → db vault use.
   * Secrets travel only as stdin frames (`--passphrase-stdin`).
   */
  async #createFileProfile(
    action: Extract<CliTuiAction, { type: 'create-file-profile' }>,
  ): Promise<void> {
    const profileId = profileIdSchema.parse(action.profileId.trim());
    const dataFile = action.dataFile.trim();
    const keyFile = action.keyFile.trim();
    if (dataFile.length === 0 || keyFile.length === 0) {
      throw new Error('dataFile and keyFile paths are required.');
    }
    if (action.passphrase.length === 0) {
      throw new Error('Passphrase is required to initialize the database.');
    }
    const recoveryFile = action.recoveryFile?.trim() ?? '';
    const recoveryPassphrase = action.recoveryPassphrase ?? '';
    const wantsRecovery = recoveryFile.length > 0 || recoveryPassphrase.length > 0;
    if (
      wantsRecovery &&
      (recoveryFile.length === 0 || recoveryPassphrase.length === 0)
    ) {
      throw new Error(
        'recoveryFile and recoveryPassphrase are both required to create a recovery kit.',
      );
    }
    const trimmedDatabaseLabel = action.databaseLabel?.trim() ?? '';
    const trimmedVaultLabel = action.vaultLabel?.trim() ?? '';
    const databaseLabel =
      trimmedDatabaseLabel.length > 0 ? trimmedDatabaseLabel : `${profileId}-db`;
    const vaultLabel =
      trimmedVaultLabel.length > 0 ? trimmedVaultLabel : `${profileId}-vault`;
    const configDirArgs = this.#configDirArgs('--config-dir');
    const profileConfigDirArgs = this.#configDirArgs('--profile-config-dir');
    let profileAdded = false;
    let vaultReady = false;

    try {
      await ensureSecureArtifactParents(
        [dataFile, keyFile, recoveryFile || null],
        this.#options.kavrixArtifactDir,
      );
      await this.#runTextCommand(
        [
          'db',
          'profile',
          'add',
          profileId,
          '--datastore',
          'file',
          '--data-file',
          dataFile,
          '--key-file',
          keyFile,
          ...configDirArgs,
        ],
        [],
      );
      profileAdded = true;

      await this.#runTextCommand(
        ['db', 'profile', 'use', profileId, ...configDirArgs],
        [],
      );

      // Frames: `kavrix frames "db init"` → [mongodb-url,] label, passphrase, passphrase-confirm
      await this.#runTextCommand(
        ['db', 'init', '--profile', profileId, ...configDirArgs, '--passphrase-stdin'],
        [databaseLabel, action.passphrase, action.passphrase],
      );

      // Frames: `kavrix frames "db vault create"` → [mongodb-url,] passphrase, label
      const created = await this.#runJsonCommand(
        [
          'db',
          'vault',
          'create',
          '--profile',
          profileId,
          ...profileConfigDirArgs,
          '--passphrase-stdin',
          '--json',
        ],
        [action.passphrase, vaultLabel],
      );
      const vaultId =
        typeof created === 'object' &&
        created !== null &&
        typeof (created as { vaultId?: unknown }).vaultId === 'string'
          ? (created as { vaultId: string }).vaultId
          : null;
      if (vaultId === null) {
        throw new Error('db vault create did not return a vaultId.');
      }

      // Frames: `kavrix frames "db vault use"` → [mongodb-url,] passphrase
      await this.#runTextCommand(
        [
          'db',
          'vault',
          'use',
          vaultId,
          '--profile',
          profileId,
          ...profileConfigDirArgs,
          '--passphrase-stdin',
        ],
        [action.passphrase],
      );

      this.#vaultId = vaultId;
      this.#recoverySlots = [];
      this.#doctorRows = [];
      this.#policyRows = [];
      this.#runPreview = null;
      this.#agentStatus = null;
      this.#browseNodes = [];
      this.#clearDatabaseUrl();
      await this.#unlock(action.passphrase);
      vaultReady = true;

      if (wantsRecovery) {
        try {
          await this.#recoveryCreate(recoveryFile, recoveryPassphrase);
          await this.#recoveryVerify(recoveryFile, recoveryPassphrase);
        } catch (recoveryError) {
          const detail =
            recoveryError instanceof Error
              ? recoveryError.message
              : 'Recovery kit create/verify failed.';
          throw new Error(
            `Vault was created for profile ${profileId}, but recovery kit setup failed: ${detail}. ` +
              `Protected state was retained. Inspect with \`kavrix db doctor health --profile ${profileId}\`, ` +
              `then create/verify with \`kavrix db recovery create|verify --profile ${profileId} --recovery-file ${recoveryFile}\` ` +
              'before relying on this profile.',
            { cause: recoveryError },
          );
        }
        this.#notice =
          `Created and selected file profile ${profileId} (vault ${vaultId}); ` +
          `recovery kit created and verified at ${recoveryFile}.`;
      } else {
        this.#notice = `Created and selected file profile ${profileId} (vault ${vaultId}).`;
      }
      this.#noticeTone = 'success';
    } catch (error) {
      if (profileAdded && !vaultReady) {
        await this.#bestEffortRemoveProfile(profileId, configDirArgs);
      }
      const detail =
        error instanceof Error ? error.message : 'File profile create failed.';
      if (vaultReady) {
        throw error instanceof Error ? error : new Error(detail, { cause: error });
      }
      throw new Error(
        profileAdded && !detail.includes('already exists')
          ? `${detail} (partial profile cleaned up when possible).`
          : detail,
        { cause: error },
      );
    }
  }

  /**
   * Matches db profile add mongodb → use → init → vault create → vault use.
   * Mongo URL + passphrase travel only as stdin frames (`--passphrase-stdin`
   * on db owner commands; `--database-url-stdin` on flat commands).
   */
  async #createMongodbProfile(
    action: Extract<CliTuiAction, { type: 'create-mongodb-profile' }>,
  ): Promise<void> {
    const profileId = profileIdSchema.parse(action.profileId.trim());
    const database = action.database.trim();
    const keyFile = action.keyFile.trim();
    const databaseUrl = action.databaseUrl.trim();
    if (database.length === 0 || keyFile.length === 0) {
      throw new Error('database name and keyFile path are required.');
    }
    if (databaseUrl.length === 0) {
      throw new Error('MongoDB URL is required (stdin frames only).');
    }
    if (action.passphrase.length === 0) {
      throw new Error('Passphrase is required to initialize the database.');
    }
    const recoveryFile = action.recoveryFile?.trim() ?? '';
    const recoveryPassphrase = action.recoveryPassphrase ?? '';
    const wantsRecovery = recoveryFile.length > 0 || recoveryPassphrase.length > 0;
    if (
      wantsRecovery &&
      (recoveryFile.length === 0 || recoveryPassphrase.length === 0)
    ) {
      throw new Error(
        'recoveryFile and recoveryPassphrase are both required to create a recovery kit.',
      );
    }
    const trimmedDatabaseLabel = action.databaseLabel?.trim() ?? '';
    const trimmedVaultLabel = action.vaultLabel?.trim() ?? '';
    const databaseLabel =
      trimmedDatabaseLabel.length > 0 ? trimmedDatabaseLabel : `${profileId}-db`;
    const vaultLabel =
      trimmedVaultLabel.length > 0 ? trimmedVaultLabel : `${profileId}-vault`;
    const configDirArgs = this.#configDirArgs('--config-dir');
    const profileConfigDirArgs = this.#configDirArgs('--profile-config-dir');
    const collectionArgs: string[] = [];
    if (action.databaseCollection?.trim()) {
      collectionArgs.push('--database-collection', action.databaseCollection.trim());
    }
    if (action.vaultCollection?.trim()) {
      collectionArgs.push('--vault-collection', action.vaultCollection.trim());
    }
    const transport = needsInsecureTransport(databaseUrl)
      ? (['--allow-insecure-transport'] as const)
      : [];
    let profileAdded = false;
    let vaultReady = false;

    try {
      await ensureSecureArtifactParents(
        [keyFile, recoveryFile || null],
        this.#options.kavrixArtifactDir,
      );
      await this.#runTextCommand(
        [
          'db',
          'profile',
          'add',
          profileId,
          '--datastore',
          'mongodb',
          '--database',
          database,
          '--key-file',
          keyFile,
          ...collectionArgs,
          ...configDirArgs,
        ],
        [],
      );
      profileAdded = true;

      await this.#runTextCommand(
        ['db', 'profile', 'use', profileId, ...configDirArgs],
        [],
      );

      this.#setDatabaseUrl(databaseUrl);

      // Frames: db init → [mongodb-url,] label, passphrase, passphrase-confirm
      await this.#runTextCommand(
        [
          'db',
          'init',
          '--profile',
          profileId,
          ...configDirArgs,
          ...transport,
          '--passphrase-stdin',
        ],
        [databaseUrl, databaseLabel, action.passphrase, action.passphrase],
      );

      // Frames: db vault create → [mongodb-url,] passphrase, label
      const created = await this.#runJsonCommand(
        [
          'db',
          'vault',
          'create',
          '--profile',
          profileId,
          ...profileConfigDirArgs,
          ...transport,
          '--passphrase-stdin',
          '--json',
        ],
        [databaseUrl, action.passphrase, vaultLabel],
      );
      const vaultId =
        typeof created === 'object' &&
        created !== null &&
        typeof (created as { vaultId?: unknown }).vaultId === 'string'
          ? (created as { vaultId: string }).vaultId
          : null;
      if (vaultId === null) {
        throw new Error('db vault create did not return a vaultId.');
      }

      await this.#runTextCommand(
        [
          'db',
          'vault',
          'use',
          vaultId,
          '--profile',
          profileId,
          ...profileConfigDirArgs,
          ...transport,
          '--passphrase-stdin',
        ],
        [databaseUrl, action.passphrase],
      );

      this.#vaultId = vaultId;
      this.#recoverySlots = [];
      this.#doctorRows = [];
      this.#policyRows = [];
      this.#runPreview = null;
      this.#agentStatus = null;
      this.#browseNodes = [];
      await this.#unlock(action.passphrase, databaseUrl);
      vaultReady = true;

      if (wantsRecovery) {
        try {
          await this.#recoveryCreate(recoveryFile, recoveryPassphrase);
          await this.#recoveryVerify(recoveryFile, recoveryPassphrase);
        } catch (recoveryError) {
          const detail =
            recoveryError instanceof Error
              ? recoveryError.message
              : 'Recovery kit create/verify failed.';
          throw new Error(
            `Vault was created for profile ${profileId}, but recovery kit setup failed: ${detail}. ` +
              `Protected state was retained. Inspect with \`kavrix db doctor health --profile ${profileId}\`, ` +
              `then create/verify with \`kavrix db recovery create|verify --profile ${profileId} --recovery-file ${recoveryFile}\` ` +
              'before relying on this profile.',
            { cause: recoveryError },
          );
        }
        this.#notice =
          `Created and selected mongodb profile ${profileId} (vault ${vaultId}); ` +
          `recovery kit created and verified at ${recoveryFile}.`;
      } else {
        this.#notice = `Created and selected mongodb profile ${profileId} (vault ${vaultId}).`;
      }
      this.#noticeTone = 'success';
    } catch (error) {
      this.#clearDatabaseUrl();
      if (profileAdded && !vaultReady) {
        await this.#bestEffortRemoveProfile(profileId, configDirArgs);
      }
      const detail =
        error instanceof Error ? error.message : 'MongoDB profile create failed.';
      if (vaultReady) {
        throw error instanceof Error ? error : new Error(detail, { cause: error });
      }
      throw new Error(
        profileAdded && !detail.includes('already exists')
          ? `${detail} (partial profile cleaned up when possible).`
          : detail,
        { cause: error },
      );
    }
  }

  async #bestEffortRemoveProfile(
    profileId: string,
    configDirArgs: readonly string[],
  ): Promise<void> {
    try {
      await this.#runTextCommand(
        ['db', 'profile', 'remove', profileId, ...configDirArgs],
        [],
      );
    } catch {
      // Honest best-effort: surface the original create error to the user.
    }
  }

  #configDirArgs(flag: '--config-dir' | '--profile-config-dir'): string[] {
    if (this.#options.profileConfigDir === undefined) return [];
    return [flag, this.#options.profileConfigDir];
  }

  async #unlock(passphrase: string, databaseUrl?: string): Promise<void> {
    if (passphrase.length === 0) {
      this.#notice = 'Passphrase required.';
      this.#noticeTone = 'warning';
      return;
    }
    if (databaseUrl !== undefined && databaseUrl.trim().length > 0) {
      this.#setDatabaseUrl(databaseUrl.trim());
    }
    const bytes = Buffer.from(passphrase, 'utf8');
    try {
      const auth = await this.#flatAuth([passphrase]);
      const names = await this.#runJsonCommand(
        [
          'list',
          ...(await this.#profileArgs()),
          ...auth.args,
          '--json',
          '--passphrase-stdin',
        ],
        auth.frames,
      );
      const parsed = names as { names?: unknown };
      if (!Array.isArray(parsed.names)) {
        throw new Error('Unexpected list response.');
      }
      this.#lock();
      this.#passphrase = Buffer.from(bytes);
      this.#credentialNames = parsed.names.filter(
        (entry): entry is string => typeof entry === 'string',
      );
      this.#notice = `Unlocked (${String(this.#credentialNames.length)} credentials).`;
      this.#noticeTone = 'success';
    } finally {
      zeroize(bytes);
    }
  }

  async #fetchCredentialValue(name: string): Promise<string> {
    if (this.#passphrase === null) {
      throw new Error('Unlock the vault before reading credentials.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const auth = await this.#flatAuth([passphrase]);
    const output = await this.#runTextCommand(
      [
        'get',
        name,
        ...(await this.#profileArgs()),
        ...auth.args,
        '--reveal',
        '--passphrase-stdin',
      ],
      auth.frames,
    );
    return output.trimEnd();
  }

  async #reveal(name: string): Promise<string> {
    const value = await this.#fetchCredentialValue(name);
    this.#notice = `REVEAL active for ${name} (15s UI timer).`;
    this.#noticeTone = 'warning';
    return value;
  }

  /**
   * Fetch the secret and write it to the clipboard without returning plaintext
   * to the TUI (copy-without-reveal). Prefers OSC 52; falls back to system.
   */
  async #copyCredential(name: string): Promise<void> {
    const secret = await this.#fetchCredentialValue(name);
    await copySecretToClipboard(secret);
    this.#notice = 'Copied (clipboard clears in ~30s)';
    this.#noticeTone = 'success';
  }

  async #putCredential(name: string, value: string): Promise<void> {
    if (this.#passphrase === null) {
      throw new Error('Unlock the vault before putting credentials.');
    }
    const trimmed = name.trim();
    if (trimmed.length === 0 || value.length === 0) {
      throw new Error('Credential name and value are required.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    // Frames contract: `kavrix frames put` → [mongodb-url,] passphrase, value
    const auth = await this.#flatAuth([passphrase, value]);
    await this.#runTextCommand(
      [
        'put',
        trimmed,
        ...(await this.#profileArgs()),
        ...auth.args,
        '--passphrase-stdin',
        '--value-stdin',
        '--overwrite',
        '--json',
      ],
      auth.frames,
    );
    await this.#refreshCredentialList();
    this.#notice = `Stored credential ${trimmed}.`;
    this.#noticeTone = 'success';
  }

  async #renameCredential(from: string, to: string): Promise<void> {
    if (this.#passphrase === null) {
      throw new Error('Unlock the vault before renaming credentials.');
    }
    const source = from.trim();
    const target = to.trim();
    if (source.length === 0 || target.length === 0) {
      throw new Error('Rename requires from and to names.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    // Frames: `kavrix frames rename` → [mongodb-url,] passphrase
    const auth = await this.#flatAuth([passphrase]);
    await this.#runTextCommand(
      [
        'rename',
        source,
        target,
        ...(await this.#profileArgs()),
        ...auth.args,
        '--passphrase-stdin',
        '--json',
      ],
      auth.frames,
    );
    await this.#refreshCredentialList();
    this.#notice = `Renamed ${source} → ${target}.`;
    this.#noticeTone = 'success';
  }

  async #removeCredential(name: string): Promise<void> {
    if (this.#passphrase === null) {
      throw new Error('Unlock the vault before removing credentials.');
    }
    const trimmed = name.trim();
    if (trimmed.length === 0) {
      throw new Error('Credential name is required.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    // Frames: `kavrix frames remove` → [mongodb-url,] passphrase
    const auth = await this.#flatAuth([passphrase]);
    await this.#runTextCommand(
      [
        'remove',
        trimmed,
        ...(await this.#profileArgs()),
        ...auth.args,
        '--passphrase-stdin',
        '--json',
      ],
      auth.frames,
    );
    await this.#refreshCredentialList();
    this.#notice = `Removed credential ${trimmed}.`;
    this.#noticeTone = 'success';
  }

  async #refreshCredentialList(): Promise<void> {
    if (this.#passphrase === null) return;
    const passphrase = this.#passphrase.toString('utf8');
    const auth = await this.#flatAuth([passphrase]);
    const names = await this.#runJsonCommand(
      [
        'list',
        ...(await this.#profileArgs()),
        ...auth.args,
        '--json',
        '--passphrase-stdin',
      ],
      auth.frames,
    );
    const parsed = names as { names?: unknown };
    if (!Array.isArray(parsed.names)) {
      throw new Error('Unexpected list response.');
    }
    this.#credentialNames = parsed.names.filter(
      (entry): entry is string => typeof entry === 'string',
    );
  }

  async #runDoctor(): Promise<void> {
    if (this.#passphrase === null) {
      this.#notice = 'Unlock before doctor.';
      this.#noticeTone = 'warning';
      return;
    }
    const passphrase = this.#passphrase.toString('utf8');
    const current = await this.#currentProfile();
    const profileArgs = await this.#profileArgs();
    let raw: unknown;
    if (current?.databaseId !== undefined) {
      const frames = await this.#ownerAuthFrames([passphrase]);
      const transport = await this.#ownerTransportArgs();
      raw = await this.#runJsonCommand(
        [
          'db',
          'doctor',
          'health',
          ...profileArgs,
          ...transport,
          '--json',
          '--passphrase-stdin',
        ],
        frames,
      );
    } else {
      const auth = await this.#flatAuth([passphrase]);
      raw = await this.#runJsonCommand(
        ['doctor', ...profileArgs, ...auth.args, '--json', '--passphrase-stdin'],
        auth.frames,
      );
    }
    this.#doctorRows = parseDoctorRows(raw);
    this.#notice = `Doctor: ${String(this.#doctorRows.length)} check(s).`;
    this.#noticeTone = this.#doctorRows.some((row) => row.status === 'error')
      ? 'error'
      : this.#doctorRows.some((row) => row.status === 'warning')
        ? 'warning'
        : 'success';
  }

  async #previewRun(credentialNames: readonly string[]): Promise<void> {
    const names = credentialNames
      .map((name) => name.trim())
      .filter((name) => name.length > 0);
    if (this.#passphrase === null) {
      throw new Error('Unlock before preview-run.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const missingLocal = names.filter((name) => !this.#credentialNames.includes(name));
    // Real CLI validation: kavrix run has no --dry-run; exercise --help + has.
    let help: string;
    try {
      help = await this.#runTextCommand(['run', '--help'], []);
    } catch (error) {
      const detail =
        error instanceof Error ? error.message : 'kavrix run --help failed';
      this.#runPreview = detail;
      this.#notice = `preview-run: ${detail}`;
      this.#noticeTone = 'error';
      return;
    }
    const usage =
      help
        .split('\n')
        .map((line) => line.trim())
        .find((line) => line.length > 0) ?? 'kavrix run --help';
    if (missingLocal.length > 0) {
      this.#runPreview = `Missing credentials: ${missingLocal.join(', ')}. ${usage}`;
      this.#notice = `preview-run: ${String(missingLocal.length)} credential(s) not in vault.`;
      this.#noticeTone = 'error';
      return;
    }
    const profileArgs = await this.#profileArgs();
    const absent: string[] = [];
    const present: string[] = [];
    for (const name of names) {
      try {
        const auth = await this.#flatAuth([passphrase]);
        const raw = await this.#runJsonCommand(
          ['has', name, ...profileArgs, ...auth.args, '--json', '--passphrase-stdin'],
          auth.frames,
        );
        const exists =
          typeof raw === 'object' &&
          raw !== null &&
          (raw as { exists?: unknown }).exists === true;
        if (exists) present.push(name);
        else absent.push(name);
      } catch (error) {
        const detail = error instanceof Error ? error.message : `has ${name} failed`;
        this.#runPreview = `CLI has failed for ${name}: ${detail}. ${usage}`;
        this.#notice = `preview-run: ${detail}`;
        this.#noticeTone = 'error';
        return;
      }
    }
    if (absent.length > 0) {
      this.#runPreview = `has absent: ${absent.join(', ')}. ${usage}`;
      this.#notice = `preview-run: ${String(absent.length)} credential(s) absent via kavrix has.`;
      this.#noticeTone = 'error';
      return;
    }
    const listed =
      names.length === 0
        ? '(none selected — unlock list + run --help checked)'
        : present.join(', ');
    this.#runPreview = `Validated ${String(names.length)} credential(s) via list+has: ${listed}. No --dry-run on kavrix run; ${usage}`;
    this.#notice = 'preview-run: list+has OK; run --help OK (no secret inject).';
    this.#noticeTone = 'success';
  }

  async #agentDryRun(
    configPath: string | undefined,
    agentName: string | undefined,
  ): Promise<void> {
    const name = agentName?.trim() ?? '';
    if (name.length === 0) {
      const detail =
        'Agent dry-run requires an agent name from the project config (kavrix agent run --agent <name> --dry-run). No default agent is invented.';
      this.#agentStatus = detail;
      this.#notice = detail;
      this.#noticeTone = 'error';
      return;
    }
    const args = ['agent', 'run', '--dry-run', '--json', '--agent', name];
    if (configPath !== undefined && configPath.trim().length > 0) {
      args.push('--config', configPath.trim());
    }
    args.push(...(await this.#profileArgs()));
    let frames: string[] = [];
    if (this.#passphrase !== null) {
      const auth = await this.#flatAuth([this.#passphrase.toString('utf8')]);
      args.push(...auth.args, '--passphrase-stdin');
      frames = auth.frames;
    }
    try {
      const raw = await this.#runJsonCommand(args, frames);
      this.#agentStatus = `agent dry-run OK: ${JSON.stringify(raw)}`;
      this.#notice = 'Agent dry-run completed.';
      this.#noticeTone = 'success';
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'agent dry-run failed';
      this.#agentStatus = detail;
      this.#notice = detail;
      this.#noticeTone = 'error';
    }
  }

  async #refreshPolicy(): Promise<void> {
    if (this.#passphrase === null) {
      throw new Error('Unlock before loading policies/grants.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const profileArgs = await this.#profileArgs();
    const auth = await this.#flatAuth([passphrase]);
    const policyRaw = await this.#runJsonCommand(
      ['policy', 'list', ...profileArgs, ...auth.args, '--json', '--passphrase-stdin'],
      auth.frames,
    );
    const grantRaw = await this.#runJsonCommand(
      ['grant', 'list', ...profileArgs, ...auth.args, '--json', '--passphrase-stdin'],
      auth.frames,
    );
    let auditRaw: unknown = { events: [] };
    try {
      auditRaw = await this.#runJsonCommand(
        [
          'audit',
          '--limit',
          '10',
          ...profileArgs,
          ...auth.args,
          '--json',
          '--passphrase-stdin',
        ],
        auth.frames,
      );
    } catch {
      // Audit is best-effort when the sidecar is empty or unavailable.
    }
    this.#policyRows = parsePolicyRows(policyRaw, grantRaw, auditRaw);
    this.#notice = `Policy snapshot: ${String(this.#policyRows.length)} row(s).`;
    this.#noticeTone = 'success';
  }

  async #policyCreate(
    action: Extract<CliTuiAction, { type: 'policy-create' }>,
  ): Promise<void> {
    if (this.#passphrase === null) {
      throw new Error('Unlock before creating a policy.');
    }
    const id = action.id.trim();
    const secret = action.secret.trim();
    const command = action.command.trim();
    if (id.length === 0 || secret.length === 0 || command.length === 0) {
      throw new Error('policy-create requires id, secret, and command.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const auth = await this.#flatAuth([passphrase]);
    const args = [
      'policy',
      'create',
      id,
      '--secret',
      secret,
      '--command',
      command,
      ...(await this.#profileArgs()),
      ...auth.args,
      '--passphrase-stdin',
      '--json',
    ];
    if (action.env !== undefined && action.env.trim().length > 0) {
      args.push('--env', action.env.trim());
    }
    await this.#runJsonCommand(args, auth.frames);
    await this.#refreshPolicy();
    this.#notice = `Created policy ${id}.`;
    this.#noticeTone = 'success';
  }

  async #policyRemove(id: string): Promise<void> {
    if (this.#passphrase === null) {
      throw new Error('Unlock before removing a policy.');
    }
    const trimmed = id.trim();
    if (trimmed.length === 0) {
      throw new Error('policy-remove requires an id.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const auth = await this.#flatAuth([passphrase]);
    await this.#runJsonCommand(
      [
        'policy',
        'remove',
        trimmed,
        ...(await this.#profileArgs()),
        ...auth.args,
        '--passphrase-stdin',
        '--json',
      ],
      auth.frames,
    );
    await this.#refreshPolicy();
    this.#notice = `Removed policy ${trimmed}.`;
    this.#noticeTone = 'success';
  }

  async #grantCreate(
    action: Extract<CliTuiAction, { type: 'grant-create' }>,
  ): Promise<void> {
    if (this.#passphrase === null) {
      throw new Error('Unlock before creating a grant.');
    }
    const secret = action.secret.trim();
    const command = action.command.trim();
    const ttl = action.ttl.trim() || '15m';
    if (secret.length === 0 || command.length === 0) {
      throw new Error('grant-create requires secret and command.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const auth = await this.#flatAuth([passphrase]);
    const args = [
      'grant',
      'create',
      secret,
      '--command',
      command,
      '--ttl',
      ttl,
      ...(await this.#profileArgs()),
      ...auth.args,
      '--passphrase-stdin',
      '--json',
    ];
    if (action.env !== undefined && action.env.trim().length > 0) {
      args.push('--env', action.env.trim());
    }
    if (action.maxUses !== undefined) {
      args.push('--max-uses', String(action.maxUses));
    }
    await this.#runJsonCommand(args, auth.frames);
    await this.#refreshPolicy();
    this.#notice = `Created grant for ${secret}.`;
    this.#noticeTone = 'success';
  }

  async #grantRevoke(grantId: string): Promise<void> {
    if (this.#passphrase === null) {
      throw new Error('Unlock before revoking a grant.');
    }
    const trimmed = grantId.trim();
    if (trimmed.length === 0) {
      throw new Error('grant-revoke requires a grant id.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const auth = await this.#flatAuth([passphrase]);
    await this.#runJsonCommand(
      [
        'grant',
        'revoke',
        trimmed,
        ...(await this.#profileArgs()),
        ...auth.args,
        '--passphrase-stdin',
        '--json',
      ],
      auth.frames,
    );
    await this.#refreshPolicy();
    this.#notice = `Revoked grant ${trimmed}.`;
    this.#noticeTone = 'success';
  }

  async #recoveryCreate(
    recoveryFile: string,
    recoveryPassphrase: string,
  ): Promise<void> {
    const file = recoveryFile.trim();
    if (file.length === 0 || recoveryPassphrase.length === 0) {
      throw new Error('recovery-create requires recoveryFile and recoveryPassphrase.');
    }
    const current = await this.#currentProfile();
    if (current === null) {
      throw new Error('Select a profile before creating recovery.');
    }
    if (current.databaseId !== undefined) {
      if (this.#passphrase === null) {
        throw new Error('Unlock before db recovery create.');
      }
      const passphrase = this.#passphrase.toString('utf8');
      const frames = await this.#ownerAuthFrames([
        passphrase,
        recoveryPassphrase,
        recoveryPassphrase,
      ]);
      const transport = await this.#ownerTransportArgs();
      await this.#runTextCommand(
        [
          'db',
          'recovery',
          'create',
          '--recovery-file',
          file,
          ...(await this.#profileArgs()),
          ...transport,
          '--passphrase-stdin',
        ],
        frames,
      );
    } else if (current.datastore === 'file') {
      if (this.#passphrase === null) {
        throw new Error('Unlock before recovery create.');
      }
      const passphrase = this.#passphrase.toString('utf8');
      await this.#runTextCommand(
        [
          'recovery',
          'create',
          '--datastore',
          'file',
          '--data-file',
          current.dataFile,
          '--key-file',
          current.keyFile,
          '--recovery-file',
          file,
          ...(this.#vaultId === null ? [] : ['--vault', this.#vaultId]),
          '--passphrase-stdin',
          '--recovery-passphrase-stdin',
        ],
        [passphrase, recoveryPassphrase],
      );
    } else {
      throw new Error('Recovery create for this profile requires the CLI.');
    }
    await this.#recoveryStatus();
    this.#notice = `Created recovery kit at ${file}.`;
    this.#noticeTone = 'success';
  }

  async #recoveryVerify(
    recoveryFile: string,
    recoveryPassphrase: string,
  ): Promise<void> {
    const file = recoveryFile.trim();
    if (file.length === 0 || recoveryPassphrase.length === 0) {
      throw new Error('recovery-verify requires recoveryFile and recoveryPassphrase.');
    }
    const current = await this.#currentProfile();
    if (current === null) {
      throw new Error('Select a profile before verifying recovery.');
    }
    if (current.databaseId !== undefined) {
      if (this.#passphrase === null) {
        throw new Error('Unlock before db recovery verify.');
      }
      const passphrase = this.#passphrase.toString('utf8');
      const frames = await this.#ownerAuthFrames([passphrase, recoveryPassphrase]);
      const transport = await this.#ownerTransportArgs();
      await this.#runTextCommand(
        [
          'db',
          'recovery',
          'verify',
          '--recovery-file',
          file,
          ...(await this.#profileArgs()),
          ...transport,
          '--passphrase-stdin',
        ],
        frames,
      );
    } else if (current.datastore === 'file') {
      await this.#runTextCommand(
        [
          'recovery',
          'verify',
          '--datastore',
          'file',
          '--data-file',
          current.dataFile,
          '--recovery-file',
          file,
          ...(this.#vaultId === null ? [] : ['--vault', this.#vaultId]),
          '--recovery-passphrase-stdin',
        ],
        [recoveryPassphrase],
      );
    } else {
      throw new Error('Recovery verify for this profile requires the CLI.');
    }
    this.#notice = `Verified recovery kit ${file}.`;
    this.#noticeTone = 'success';
  }

  async #recoveryRevoke(slotId: string): Promise<void> {
    const trimmed = slotId.trim();
    if (trimmed.length === 0) {
      throw new Error('recovery-revoke requires a slot id.');
    }
    const active = this.#recoverySlots.filter((slot) => slot.status === 'active');
    if (active.length <= 1) {
      throw new Error(
        'Cannot revoke the last active recovery slot (CLI refuses final-slot revoke).',
      );
    }
    const current = await this.#currentProfile();
    if (current === null) {
      throw new Error('Select a profile before revoking recovery.');
    }
    if (current.databaseId !== undefined) {
      if (this.#passphrase === null) {
        throw new Error('Unlock before db recovery revoke.');
      }
      const passphrase = this.#passphrase.toString('utf8');
      const frames = await this.#ownerAuthFrames([passphrase]);
      const transport = await this.#ownerTransportArgs();
      await this.#runTextCommand(
        [
          'db',
          'recovery',
          'revoke',
          trimmed,
          ...(await this.#profileArgs()),
          ...transport,
          '--passphrase-stdin',
        ],
        frames,
      );
    } else if (current.datastore === 'file') {
      if (this.#passphrase === null) {
        throw new Error('Unlock before recovery revoke.');
      }
      const passphrase = this.#passphrase.toString('utf8');
      await this.#runTextCommand(
        [
          'recovery',
          'revoke',
          trimmed,
          '--datastore',
          'file',
          '--data-file',
          current.dataFile,
          '--key-file',
          current.keyFile,
          ...(this.#vaultId === null ? [] : ['--vault', this.#vaultId]),
          '--passphrase-stdin',
        ],
        [passphrase],
      );
    } else {
      throw new Error('Recovery revoke for this profile requires the CLI.');
    }
    await this.#recoveryStatus();
    this.#notice = `Revoked recovery slot ${trimmed}.`;
    this.#noticeTone = 'success';
  }

  async #recoveryStatus(): Promise<void> {
    const current = await this.#currentProfile();
    if (current === null) {
      this.#notice = 'Select a profile before loading recovery status.';
      this.#noticeTone = 'warning';
      return;
    }

    if (current.databaseId !== undefined) {
      if (this.#passphrase === null) {
        this.#notice = 'Unlock before db recovery status.';
        this.#noticeTone = 'warning';
        return;
      }
      const passphrase = this.#passphrase.toString('utf8');
      const frames = await this.#ownerAuthFrames([passphrase]);
      const transport = await this.#ownerTransportArgs();
      const raw = await this.#runJsonCommand(
        [
          'db',
          'recovery',
          'status',
          ...(await this.#profileArgs()),
          ...transport,
          '--json',
          '--passphrase-stdin',
        ],
        frames,
      );
      this.#recoverySlots = parseRecoverySlots(raw, 'db');
      this.#notice = `Recovery status: ${String(this.#recoverySlots.length)} slot(s).`;
      this.#noticeTone = 'success';
      return;
    }

    // Legacy / unbound file vault: `kavrix recovery status` (no secrets).
    if (current.datastore === 'file') {
      const raw = await this.#runJsonCommand(
        [
          'recovery',
          'status',
          '--datastore',
          'file',
          '--data-file',
          current.dataFile,
          '--json',
          ...(this.#vaultId === null ? [] : ['--vault', this.#vaultId]),
        ],
        [],
      );
      this.#recoverySlots = parseRecoverySlots(raw, 'legacy');
      this.#notice = `Recovery status: ${String(this.#recoverySlots.length)} slot(s).`;
      this.#noticeTone = 'success';
      return;
    }

    this.#notice =
      'Recovery status for this profile requires CLI (`kavrix recovery status` / `db recovery status`).';
    this.#noticeTone = 'info';
  }

  async #refreshBrowse(): Promise<void> {
    if (this.#passphrase === null) {
      this.#browseNodes = [
        {
          id: 'locked',
          kind: 'context',
          label: '(locked)',
          detail: 'Unlock to load kavrix context / service / item lists.',
        },
      ];
      this.#notice = 'Browse locked — unlock first.';
      this.#noticeTone = 'warning';
      return;
    }
    const passphrase = this.#passphrase.toString('utf8');
    const profileArgs = await this.#profileArgs();
    const vaultArgs = this.#vaultFlagArgs();
    const auth = await this.#flatAuth([passphrase]);
    const nodes: {
      id: string;
      kind: 'context' | 'service' | 'item' | 'field';
      label: string;
      detail: string;
    }[] = [];
    try {
      const contextRaw = await this.#runJsonCommand(
        [
          'context',
          'list',
          ...profileArgs,
          ...vaultArgs,
          ...auth.args,
          '--json',
          '--passphrase-stdin',
        ],
        auth.frames,
      );
      const contexts =
        typeof contextRaw === 'object' &&
        contextRaw !== null &&
        Array.isArray((contextRaw as { contexts?: unknown }).contexts)
          ? (contextRaw as { contexts: unknown[] }).contexts.flatMap((entry) => {
              if (typeof entry === 'string') return [entry];
              if (
                typeof entry === 'object' &&
                entry !== null &&
                typeof (entry as { name?: unknown }).name === 'string'
              ) {
                return [(entry as { name: string }).name];
              }
              return [];
            })
          : [];
      if (contexts.length === 0) {
        nodes.push({
          id: 'contexts-empty',
          kind: 'context',
          label: '(none)',
          detail: 'kavrix context list returned no project contexts.',
        });
      }
      for (const contextName of contexts.slice(0, 20)) {
        nodes.push({
          id: `context:${contextName}`,
          kind: 'context',
          label: contextName,
          detail: 'project context',
        });
        try {
          const serviceRaw = await this.#runJsonCommand(
            [
              'service',
              'list',
              '--context',
              contextName,
              ...profileArgs,
              ...vaultArgs,
              ...auth.args,
              '--json',
              '--passphrase-stdin',
            ],
            auth.frames,
          );
          const services =
            typeof serviceRaw === 'object' &&
            serviceRaw !== null &&
            Array.isArray((serviceRaw as { services?: unknown }).services)
              ? (serviceRaw as { services: unknown[] }).services.filter(
                  (entry): entry is string => typeof entry === 'string',
                )
              : [];
          for (const serviceName of services.slice(0, 20)) {
            nodes.push({
              id: `service:${contextName}/${serviceName}`,
              kind: 'service',
              label: serviceName,
              detail: `context ${contextName}`,
            });
            try {
              const itemRaw = await this.#runJsonCommand(
                [
                  'item',
                  'list',
                  '--context',
                  contextName,
                  '--service',
                  serviceName,
                  ...profileArgs,
                  ...vaultArgs,
                  ...auth.args,
                  '--json',
                  '--passphrase-stdin',
                ],
                auth.frames,
              );
              const items =
                typeof itemRaw === 'object' &&
                itemRaw !== null &&
                Array.isArray((itemRaw as { items?: unknown }).items)
                  ? (itemRaw as { items: unknown[] }).items.filter(
                      (entry): entry is string => typeof entry === 'string',
                    )
                  : [];
              for (const itemTitle of items.slice(0, 30)) {
                nodes.push({
                  id: `item:${contextName}/${serviceName}/${itemTitle}`,
                  kind: 'item',
                  label: itemTitle,
                  detail: `service ${serviceName}`,
                });
              }
            } catch (error) {
              const detail =
                error instanceof Error ? error.message : 'item list failed';
              nodes.push({
                id: `item-error:${contextName}/${serviceName}`,
                kind: 'item',
                label: '(error)',
                detail,
              });
            }
          }
        } catch (error) {
          const detail = error instanceof Error ? error.message : 'service list failed';
          nodes.push({
            id: `service-error:${contextName}`,
            kind: 'service',
            label: '(error)',
            detail,
          });
        }
      }
      this.#browseNodes = nodes;
      this.#notice = `Browse: ${String(nodes.length)} node(s) from context/service/item list.`;
      this.#noticeTone = 'success';
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'context list failed';
      this.#browseNodes = [
        {
          id: 'error',
          kind: 'context',
          label: '(error)',
          detail,
        },
      ];
      this.#notice = `Browse: ${detail}`;
      this.#noticeTone = 'error';
    }
  }

  async #currentProfile(): Promise<DatastoreProfile | null> {
    const registry = await DatastoreProfileRegistry.openIfPresent({
      ...(this.#options.profileConfigDir === undefined
        ? {}
        : { configDirectory: this.#options.profileConfigDir }),
    });
    if (registry === null) return null;
    return registry.current();
  }

  #lock(): void {
    if (this.#passphrase !== null) {
      zeroize(this.#passphrase);
      this.#passphrase = null;
    }
    this.#credentialNames = [];
    this.#clearDatabaseUrl();
  }

  #setDatabaseUrl(url: string): void {
    this.#clearDatabaseUrl();
    if (url.length > 0) {
      this.#databaseUrl = Buffer.from(url, 'utf8');
    }
  }

  #clearDatabaseUrl(): void {
    if (this.#databaseUrl !== null) {
      zeroize(this.#databaseUrl);
      this.#databaseUrl = null;
    }
  }

  #requireDatabaseUrl(): string {
    if (this.#databaseUrl === null) {
      throw new Error(
        'MongoDB URL required. Unlock again and provide the connection string (stdin frames only).',
      );
    }
    return this.#databaseUrl.toString('utf8');
  }

  async #ownerAuthFrames(rest: readonly string[]): Promise<string[]> {
    const current = await this.#currentProfile();
    if (current?.datastore === 'mongodb') {
      return [this.#requireDatabaseUrl(), ...rest];
    }
    return [...rest];
  }

  async #ownerTransportArgs(): Promise<string[]> {
    const current = await this.#currentProfile();
    if (current?.datastore !== 'mongodb' || this.#databaseUrl === null) {
      return [];
    }
    return needsInsecureTransport(this.#databaseUrl.toString('utf8'))
      ? ['--allow-insecure-transport']
      : [];
  }

  async #flatAuth(
    rest: readonly string[],
  ): Promise<{ args: string[]; frames: string[] }> {
    const current = await this.#currentProfile();
    if (current?.datastore === 'mongodb') {
      const url = this.#requireDatabaseUrl();
      const insecure = needsInsecureTransport(url)
        ? (['--allow-insecure-transport'] as const)
        : [];
      return {
        args: ['--database-url-stdin', ...insecure],
        frames: [url, ...rest],
      };
    }
    return { args: [], frames: [...rest] };
  }

  #vaultFlagArgs(): string[] {
    return this.#vaultId === null ? [] : ['--vault', this.#vaultId];
  }

  async #profileArgs(): Promise<string[]> {
    const args: string[] = [];
    if (this.#options.profileConfigDir !== undefined) {
      args.push('--profile-config-dir', this.#options.profileConfigDir);
    }
    const registry = await DatastoreProfileRegistry.openIfPresent({
      ...(this.#options.profileConfigDir === undefined
        ? {}
        : { configDirectory: this.#options.profileConfigDir }),
    });
    const current = registry === null ? null : await registry.current();
    if (current !== null) {
      args.push('--profile', current.id);
    }
    return args;
  }

  #binPath(): string {
    if (this.#options.binPath !== undefined) return this.#options.binPath;
    try {
      return require.resolve('kavrix/dist/bin.js');
    } catch {
      const here = dirname(fileURLToPath(import.meta.url));
      return join(here, 'bin.js');
    }
  }

  async #runJsonCommand(
    args: readonly string[],
    frames: readonly string[],
  ): Promise<unknown> {
    const text = await this.#runTextCommand(args, frames);
    return JSON.parse(text) as unknown;
  }

  async #runTextCommand(
    args: readonly string[],
    frames: readonly string[],
  ): Promise<string> {
    if (this.#options.commandRunner !== undefined) {
      return this.#options.commandRunner(args, frames);
    }
    const bin = this.#binPath();
    const env = { ...process.env };
    delete env['FORCE_COLOR'];
    const child = spawn(process.execPath, [bin, ...args], {
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    const payload = frames.map((frame) => `${frame}\n`).join('');
    child.stdin.end(payload, 'utf8');
    const code = await new Promise<number | null>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (exitCode) => {
        resolve(exitCode);
      });
    });
    if (code !== 0) {
      const detail = Buffer.concat(stderr).toString('utf8').trim() || 'CLI failed.';
      throw new Error(detail.split('\n')[0] ?? 'CLI failed.');
    }
    return Buffer.concat(stdout).toString('utf8');
  }
}

function needsInsecureTransport(databaseUrl: string): boolean {
  try {
    const parsed = new URL(databaseUrl);
    const host = parsed.hostname.replace(/^\[|\]$/gu, '').toLowerCase();
    return host !== 'localhost' && host !== '127.0.0.1' && host !== '::1';
  } catch {
    return true;
  }
}

function describeProfile(profile: DatastoreProfile): string {
  if (profile.datastore === 'file') {
    return `file ${profile.dataFile}`;
  }
  return `mongodb ${profile.database}/${profile.vaultCollection}`;
}

function parseRecoverySlots(
  raw: unknown,
  mode: 'db' | 'legacy',
): CliTuiSnapshot['recovery'] {
  if (typeof raw !== 'object' || raw === null) {
    return [
      {
        slotId: '(unavailable)',
        status: 'active',
        detail: 'Unexpected recovery status payload.',
      },
    ];
  }
  const record = raw as Record<string, unknown>;
  const slots = Array.isArray(record['slots']) ? record['slots'] : [];
  if (slots.length === 0) {
    const active =
      typeof record['active'] === 'number'
        ? record['active']
        : typeof record['activeKits'] === 'number'
          ? record['activeKits']
          : 0;
    const revoked =
      typeof record['revoked'] === 'number'
        ? record['revoked']
        : typeof record['revokedKits'] === 'number'
          ? record['revokedKits']
          : 0;
    return [
      {
        slotId: '(none)',
        status: 'active',
        detail: `${mode} recovery: ${String(active)} active, ${String(revoked)} revoked.`,
      },
    ];
  }
  return slots.flatMap((entry) => {
    if (typeof entry !== 'object' || entry === null) return [];
    const slot = entry as Record<string, unknown>;
    const id =
      typeof slot['id'] === 'string'
        ? slot['id']
        : typeof slot['slotId'] === 'string'
          ? slot['slotId']
          : null;
    if (id === null) return [];
    const stateRaw = slot['state'] ?? slot['status'];
    const status: 'active' | 'revoked' = stateRaw === 'revoked' ? 'revoked' : 'active';
    const createdAt =
      typeof slot['createdAt'] === 'string' ? ` created ${slot['createdAt']}` : '';
    return [
      {
        slotId: id,
        status,
        detail: `${status}${createdAt}`,
      },
    ];
  });
}

function parseDoctorRows(raw: unknown): CliTuiSnapshot['doctor'] {
  if (typeof raw !== 'object' || raw === null) {
    return [
      {
        name: 'doctor',
        status: 'error',
        detail: 'Unexpected doctor payload.',
      },
    ];
  }
  const record = raw as Record<string, unknown>;
  const checks = Array.isArray(record['checks']) ? record['checks'] : null;
  if (checks !== null && checks.length > 0) {
    return checks.flatMap((entry) => {
      if (typeof entry !== 'object' || entry === null) return [];
      const check = entry as Record<string, unknown>;
      const name =
        typeof check['name'] === 'string'
          ? check['name']
          : typeof check['id'] === 'string'
            ? check['id']
            : 'check';
      const statusRaw = check['status'];
      let status: 'ok' | 'warning' | 'error' = 'ok';
      if (statusRaw === 'warning' || statusRaw === 'warn' || statusRaw === 'degraded') {
        status = 'warning';
      } else if (
        statusRaw === 'error' ||
        statusRaw === 'manual-recovery' ||
        statusRaw === 'fail' ||
        statusRaw === 'failed'
      ) {
        status = 'error';
      }
      const detail =
        typeof check['detail'] === 'string'
          ? check['detail']
          : typeof check['message'] === 'string'
            ? check['message']
            : typeof statusRaw === 'string'
              ? statusRaw
              : 'ok';
      return [{ name, status, detail }];
    });
  }
  const rows: {
    name: string;
    status: 'ok' | 'warning' | 'error';
    detail: string;
  }[] = [];
  if (typeof record['healthy'] === 'boolean') {
    rows.push({
      name: 'healthy',
      status: record['healthy'] ? 'ok' : 'error',
      detail: record['healthy'] ? 'Vault authenticated.' : 'Vault unhealthy.',
    });
  }
  if (typeof record['credentialCount'] === 'number') {
    rows.push({
      name: 'credentials',
      status: 'ok',
      detail: `${String(record['credentialCount'])} credential(s).`,
    });
  }
  if (typeof record['revision'] === 'number') {
    rows.push({
      name: 'revision',
      status: 'ok',
      detail: `revision ${String(record['revision'])}`,
    });
  }
  if (typeof record['vaultId'] === 'string') {
    rows.push({
      name: 'vault',
      status: 'ok',
      detail: record['vaultId'],
    });
  }
  if (rows.length === 0) {
    rows.push({
      name: 'doctor',
      status: 'ok',
      detail: 'Doctor completed (no structured checks).',
    });
  }
  return rows;
}

function parsePolicyRows(
  policyRaw: unknown,
  grantRaw: unknown,
  auditRaw: unknown,
): CliTuiSnapshot['policies'] {
  const rows: {
    id: string;
    kind: 'policy' | 'grant' | 'audit';
    summary: string;
    status?: 'active' | 'expired' | 'exhausted' | 'revoked' | 'clock-invalid';
  }[] = [];
  if (typeof policyRaw === 'object' && policyRaw !== null) {
    const policies = (policyRaw as Record<string, unknown>)['policies'];
    if (Array.isArray(policies)) {
      for (const entry of policies) {
        if (typeof entry !== 'object' || entry === null) continue;
        const policy = entry as Record<string, unknown>;
        const id = typeof policy['id'] === 'string' ? policy['id'] : null;
        if (id === null) continue;
        const secret = typeof policy['secret'] === 'string' ? policy['secret'] : '?';
        const commands = Array.isArray(policy['commands'])
          ? policy['commands'].filter(
              (item): item is string => typeof item === 'string',
            )
          : [];
        rows.push({
          id,
          kind: 'policy',
          summary: `secret=${secret} cmds=${commands.join(',') || '(none)'}`,
        });
      }
    }
  }
  if (typeof grantRaw === 'object' && grantRaw !== null) {
    const grants = (grantRaw as Record<string, unknown>)['grants'];
    if (Array.isArray(grants)) {
      for (const entry of grants) {
        if (typeof entry !== 'object' || entry === null) continue;
        const grant = entry as Record<string, unknown>;
        const id =
          typeof grant['grantId'] === 'string'
            ? grant['grantId']
            : typeof grant['id'] === 'string'
              ? grant['id']
              : null;
        if (id === null) continue;
        const secret = typeof grant['secret'] === 'string' ? grant['secret'] : '?';
        const rawStatus =
          typeof grant['status'] === 'string' ? grant['status'] : 'unknown';
        const status =
          rawStatus === 'active' ||
          rawStatus === 'expired' ||
          rawStatus === 'exhausted' ||
          rawStatus === 'revoked' ||
          rawStatus === 'clock-invalid'
            ? rawStatus
            : undefined;
        rows.push({
          id,
          kind: 'grant',
          summary: `secret=${secret} status=${rawStatus}`,
          ...(status === undefined ? {} : { status }),
        });
      }
    }
  }
  if (typeof auditRaw === 'object' && auditRaw !== null) {
    const events = (auditRaw as Record<string, unknown>)['events'];
    if (Array.isArray(events)) {
      for (const entry of events.slice(-8)) {
        if (typeof entry !== 'object' || entry === null) continue;
        const event = entry as Record<string, unknown>;
        const action = typeof event['action'] === 'string' ? event['action'] : 'event';
        const at = typeof event['at'] === 'string' ? event['at'] : '';
        rows.push({
          id: `audit:${at}:${action}`,
          kind: 'audit',
          summary: at.length > 0 ? `${action} @ ${at}` : action,
        });
      }
    }
  }
  if (rows.length === 0) {
    rows.push({
      id: '(empty)',
      kind: 'audit',
      summary: 'No policies, grants, or recent audit events.',
    });
  }
  return rows;
}
