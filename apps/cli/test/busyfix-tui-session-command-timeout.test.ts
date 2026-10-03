import { existsSync } from 'node:fs';
import { rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { profileIdSchema } from '@kavrix/schemas';
import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import {
  MAX_TUI_COMMAND_TIMEOUT_MS,
  TUI_COMMAND_KILL_GRACE_MS,
  TUI_COMMAND_TIMEOUT_MS,
  createCliTuiBackend,
} from '../src/tui-session.js';

// The TUI host backend spawns a real `kavrix` child for every backend intent.
// A child that never exits (native keychain prompt, stalled MongoDB handshake,
// OS dialog) used to await `close` forever, so `packages/tui`'s `busy` flag
// stayed set and every intent was dropped: a permanently frozen TUI. These
// tests drive the real spawn path through a stand-in `binPath`, because the
// production child is the same `process.execPath` + script invocation.

const CHILD_TIMEOUT_MS = 750;
const CHILD_SURVIVAL_MARKER_DELAY_MS = 2_500;
/** Generous ceiling for "settled near the deadline", still far below a hang. */
const SETTLE_CEILING_MS = 5_000;

describe('CliTuiSession child command bounding', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    await Promise.all(
      dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
    );
  });

  async function setupUnboundFileProfile(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'kavrix-tui-timeout-'));
    dirs.push(dir);
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: dir,
    });
    // No databaseId: `recovery-status` then takes the legacy file branch, which
    // needs no unlock passphrase and therefore carries no secret into the child.
    await registry.add({
      id: profileIdSchema.parse('timeout'),
      datastore: 'file',
      dataFile: join(dir, 'db.kavrix'),
      keyFile: join(dir, 'owner.key'),
    });
    await registry.use(profileIdSchema.parse('timeout'));
    return dir;
  }

  /** Stand-in for the `kavrix` entry point the session spawns by `binPath`. */
  async function writeScript(dir: string, name: string, body: string): Promise<string> {
    const path = join(dir, name);
    await writeFile(path, body, 'utf8');
    return path;
  }

  it('publishes a bounded default timeout for the child command boundary', () => {
    expect(Number.isSafeInteger(TUI_COMMAND_TIMEOUT_MS)).toBe(true);
    expect(TUI_COMMAND_TIMEOUT_MS).toBeGreaterThan(0);
    expect(TUI_COMMAND_TIMEOUT_MS).toBeLessThanOrEqual(5 * 60_000);
  });

  it('publishes a finite ceiling so a caller cannot remove the bound', () => {
    // Without a ceiling `Number.MAX_SAFE_INTEGER` passes an `isSafeInteger`
    // check while making the deadline effectively unbounded, which is precisely
    // what the deadline exists to prevent.
    expect(Number.isSafeInteger(MAX_TUI_COMMAND_TIMEOUT_MS)).toBe(true);
    expect(MAX_TUI_COMMAND_TIMEOUT_MS).toBeGreaterThan(TUI_COMMAND_TIMEOUT_MS);
    expect(MAX_TUI_COMMAND_TIMEOUT_MS).toBeLessThanOrEqual(60 * 60_000);
    expect(Number.isSafeInteger(TUI_COMMAND_KILL_GRACE_MS)).toBe(true);
    expect(TUI_COMMAND_KILL_GRACE_MS).toBeGreaterThan(0);
    expect(TUI_COMMAND_KILL_GRACE_MS).toBeLessThan(TUI_COMMAND_TIMEOUT_MS);
  });

  it('bounds a child that never exits and reports a distinct timeout notice', async () => {
    const dir = await setupUnboundFileProfile();
    const marker = join(dir, 'child-survived.txt');
    const binPath = await writeScript(
      dir,
      'hanging-child.mjs',
      [
        "import { writeFileSync } from 'node:fs';",
        `setTimeout(() => { writeFileSync(${JSON.stringify(marker)}, 'alive'); }, ${String(CHILD_SURVIVAL_MARKER_DELAY_MS)});`,
        'setInterval(() => undefined, 250);',
        '',
      ].join('\n'),
    );

    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      binPath,
      commandTimeoutMs: CHILD_TIMEOUT_MS,
    });

    const startedAt = Date.now();
    const result = await backend.dispatch({ type: 'recovery-status' });
    const elapsed = Date.now() - startedAt;

    // Bounded: the dispatch settles near the timeout instead of hanging forever.
    // The ceiling is tight enough that a deadline which never fires fails here.
    expect(elapsed).toBeLessThanOrEqual(CHILD_TIMEOUT_MS + SETTLE_CEILING_MS);
    expect(result.snapshot.noticeTone).toBe('error');
    expect(result.snapshot.notice).toMatch(/did not finish/iu);
    // Distinct from an ordinary nonzero exit, which reports the CLI's own
    // stderr line (see the sibling test below).
    expect(result.snapshot.notice).not.toBe('CLI failed.');
    // Generic: no child arguments, data file, key file, or profile path leak
    // into the notice.
    expect(result.snapshot.notice).not.toContain(binPath);
    expect(result.snapshot.notice).not.toContain(dir);

    // Terminated, not merely abandoned: the child never reaches its survival
    // marker.
    await new Promise((resolve) =>
      setTimeout(resolve, CHILD_SURVIVAL_MARKER_DELAY_MS + 1_500),
    );
    expect(existsSync(marker)).toBe(false);
  });

  it('keeps the existing nonzero-exit semantics for a child that answers', async () => {
    const dir = await setupUnboundFileProfile();
    const binPath = await writeScript(
      dir,
      'failing-child.mjs',
      [
        "process.stderr.write('vault file is unreadable\\n');",
        'process.exit(4);',
        '',
      ].join('\n'),
    );

    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      binPath,
      commandTimeoutMs: CHILD_TIMEOUT_MS,
    });

    const result = await backend.dispatch({ type: 'recovery-status' });
    expect(result.snapshot.noticeTone).toBe('error');
    expect(result.snapshot.notice).toBe('vault file is unreadable');
  });

  it('keeps the existing success semantics for a child that exits zero', async () => {
    const dir = await setupUnboundFileProfile();
    const binPath = await writeScript(
      dir,
      'succeeding-child.mjs',
      [
        "process.stdout.write(JSON.stringify({ slots: [{ slotId: 'slot_a', status: 'active' }] }));",
        '',
      ].join('\n'),
    );

    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      binPath,
      commandTimeoutMs: CHILD_TIMEOUT_MS,
    });

    const result = await backend.dispatch({ type: 'recovery-status' });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.notice).toBe('Recovery status: 1 slot(s).');
    expect(result.snapshot.recovery[0]?.slotId).toBe('slot_a');
  });

  it('rejects every out-of-range timeout override before spawning a child', async () => {
    const dir = await setupUnboundFileProfile();
    // Each script records that it ran, so a rejected override is proven not to
    // have reached the spawn rather than merely reporting a notice.
    const markers = {
      nan: join(dir, 'ran-nan.txt'),
      negative: join(dir, 'ran-negative.txt'),
      fraction: join(dir, 'ran-fraction.txt'),
      unbounded: join(dir, 'ran-unbounded.txt'),
    };
    const binPath = await writeScript(
      dir,
      'marker-child.mjs',
      [
        "import { writeFileSync } from 'node:fs';",
        "import { argv } from 'node:process';",
        'const tag = argv[2] ?? "none";',
        `writeFileSync([${Object.values(markers)
          .map((marker) => JSON.stringify(marker))
          .join(', ')}].find((p) => p.includes(tag)) ?? "", 'ran');`,
        'process.stdout.write(\'{"slots":[]}\');',
        '',
      ].join('\n'),
    );

    const rejected: readonly Readonly<{ label: string; value: number }>[] = [
      { label: 'zero', value: 0 },
      { label: 'negative', value: -1 },
      { label: 'nan', value: Number.NaN },
      { label: 'infinity', value: Number.POSITIVE_INFINITY },
      { label: 'fraction', value: 12.5 },
      // Safe integer, yet past the ceiling: this is the case a bare
      // `isSafeInteger` guard lets through.
      { label: 'unbounded', value: Number.MAX_SAFE_INTEGER },
      { label: 'past-ceiling', value: MAX_TUI_COMMAND_TIMEOUT_MS + 1 },
    ];

    for (const entry of rejected) {
      const backend = createCliTuiBackend({
        profileConfigDir: dir,
        ascii: true,
        binPath,
        commandTimeoutMs: entry.value,
      });

      const result = await backend.dispatch({ type: 'recovery-status' });
      expect(result.snapshot.noticeTone, entry.label).toBe('error');
      expect(result.snapshot.notice, entry.label).toMatch(/invalid command timeout/iu);
      // The rejected value must never be echoed back into the notice.
      expect(result.snapshot.notice, entry.label).not.toContain(String(entry.value));
    }

    expect(Object.values(markers).some((marker) => existsSync(marker))).toBe(false);
  });

  it('accepts a deadline exactly on the ceiling', async () => {
    const dir = await setupUnboundFileProfile();
    const binPath = await writeScript(
      dir,
      'ceiling-child.mjs',
      ['process.stdout.write(\'{"slots":[]}\');', ''].join('\n'),
    );

    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      binPath,
      commandTimeoutMs: MAX_TUI_COMMAND_TIMEOUT_MS,
    });

    const result = await backend.dispatch({ type: 'recovery-status' });
    expect(result.snapshot.noticeTone).toBe('success');
  });

  it('survives a child that exits before the frames are written', async () => {
    const dir = await setupUnboundFileProfile();
    // A child that closes stdin immediately makes the parent's write fail with
    // EPIPE. An unhandled stream error would take the whole TUI process down.
    const binPath = await writeScript(
      dir,
      'early-exit-child.mjs',
      [
        'process.stdin.destroy();',
        "process.stderr.write('vault file is unreadable\\n');",
        'process.exit(9);',
        '',
      ].join('\n'),
    );

    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      binPath,
      commandTimeoutMs: CHILD_TIMEOUT_MS,
    });

    const result = await backend.dispatch({ type: 'recovery-status' });
    expect(result.snapshot.noticeTone).toBe('error');
    expect(result.snapshot.notice).toBe('vault file is unreadable');
  });
});
