import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { zeroize } from '@kavrix/crypto';
import { profileIdSchema } from '@kavrix/schemas';

import {
  DatastoreProfileRegistry,
  type DatastoreProfile,
} from './datastore-profiles.js';

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
  | Readonly<{ type: 'preview-run'; credentialNames: readonly string[] }>
  | Readonly<{ type: 'agent-dry-run' }>
  | Readonly<{ type: 'refresh-policy' }>
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
  readonly binPath?: string;
  /** Optional injectable CLI runner (tests); secrets stay in frames only. */
  readonly commandRunner?: CliTuiCommandRunner;
}

export function createCliTuiBackend(
  options: CliTuiSessionOptions = {},
): CliTuiBackend {
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
        case 'use-vault':
          this.#vaultId = action.vaultId;
          this.#notice = `Selected vault ${action.vaultId}.`;
          this.#noticeTone = 'success';
          break;
        case 'unlock':
          await this.#unlock(action.passphrase);
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
        case 'preview-run':
          this.#notice = `Dry run preview for: ${action.credentialNames.join(', ') || '(none)'}`;
          this.#noticeTone = 'success';
          break;
        case 'agent-dry-run':
          this.#notice = 'Agent dry-run: no broker socket opened from TUI.';
          this.#noticeTone = 'info';
          break;
        case 'refresh-policy':
          this.#notice = 'Policy/grant/audit: open via CLI for mutations.';
          this.#noticeTone = 'info';
          break;
        case 'refresh-browse':
          this.#notice = 'Structured browse refreshed from session metadata.';
          this.#noticeTone = 'info';
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
              detail: 'Open Recovery to load status from kavrix recovery / db recovery.',
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
        this.#passphrase === null
          ? [
              {
                name: 'session',
                status: 'warning',
                detail: 'Unlock to run authenticated doctor checks.',
              },
            ]
          : [
              {
                name: 'session',
                status: 'ok',
                detail: `Unlocked with ${String(this.#credentialNames.length)} credentials.`,
              },
            ],
      recovery,
      policies: [
        {
          id: 'runtime',
          kind: 'audit',
          summary: 'Authorization mutations remain CLI-gated.',
        },
      ],
      browse: [
        {
          id: 'root',
          kind: 'context',
          label: current?.id ?? '(none)',
          detail: 'Structured context/service/item browse uses vault projection.',
        },
      ],
      runPreview:
        this.#credentialNames.length === 0
          ? 'Unlock and press p to dry-preview credential injection.'
          : `Available: ${this.#credentialNames.slice(0, 8).join(', ')}`,
      agentStatus: 'Agent broker idle (dry-run only from TUI).',
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
    this.#recoverySlots = [];
    this.#notice = `Selected profile ${profileId}.`;
    this.#noticeTone = 'success';
  }

  async #unlock(passphrase: string): Promise<void> {
    if (passphrase.length === 0) {
      this.#notice = 'Passphrase required.';
      this.#noticeTone = 'warning';
      return;
    }
    const bytes = Buffer.from(passphrase, 'utf8');
    try {
      const names = await this.#runJsonCommand(
        ['list', ...(await this.#profileArgs()), '--json', '--passphrase-stdin'],
        [passphrase],
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

  async #reveal(name: string): Promise<string> {
    if (this.#passphrase === null) {
      throw new Error('Unlock the vault before revealing.');
    }
    const passphrase = this.#passphrase.toString('utf8');
    const output = await this.#runTextCommand(
      ['get', name, ...(await this.#profileArgs()), '--reveal', '--passphrase-stdin'],
      [passphrase],
    );
    this.#notice = `REVEAL active for ${name} (15s UI timer).`;
    this.#noticeTone = 'warning';
    return output.trimEnd();
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
    await this.#runTextCommand(
      [
        'put',
        trimmed,
        ...(await this.#profileArgs()),
        '--passphrase-stdin',
        '--value-stdin',
        '--overwrite',
        '--json',
      ],
      [passphrase, value],
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
    await this.#runTextCommand(
      [
        'rename',
        source,
        target,
        ...(await this.#profileArgs()),
        '--passphrase-stdin',
        '--json',
      ],
      [passphrase],
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
    await this.#runTextCommand(
      [
        'remove',
        trimmed,
        ...(await this.#profileArgs()),
        '--passphrase-stdin',
        '--json',
      ],
      [passphrase],
    );
    await this.#refreshCredentialList();
    this.#notice = `Removed credential ${trimmed}.`;
    this.#noticeTone = 'success';
  }

  async #refreshCredentialList(): Promise<void> {
    if (this.#passphrase === null) return;
    const passphrase = this.#passphrase.toString('utf8');
    const names = await this.#runJsonCommand(
      ['list', ...(await this.#profileArgs()), '--json', '--passphrase-stdin'],
      [passphrase],
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
    await this.#runJsonCommand(
      ['doctor', ...(await this.#profileArgs()), '--passphrase-stdin'],
      [passphrase],
    );
    this.#notice = 'Doctor completed.';
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
      const raw = await this.#runJsonCommand(
        [
          'db',
          'recovery',
          'status',
          ...(await this.#profileArgs()),
          '--json',
          '--passphrase-stdin',
        ],
        [passphrase],
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
    child.stdout?.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr?.on('data', (chunk: Buffer) => stderr.push(chunk));
    const payload = frames.map((frame) => `${frame}\n`).join('');
    child.stdin?.end(payload, 'utf8');
    const code = await new Promise<number | null>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (exitCode) => resolve(exitCode));
    });
    if (code !== 0) {
      const detail = Buffer.concat(stderr).toString('utf8').trim() || 'CLI failed.';
      throw new Error(detail.split('\n')[0] ?? 'CLI failed.');
    }
    return Buffer.concat(stdout).toString('utf8');
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
    const status: 'active' | 'revoked' =
      stateRaw === 'revoked' ? 'revoked' : 'active';
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
