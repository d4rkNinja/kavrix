import { describe, expect, it } from 'vitest';
import {
  executionReference,
  permissionEntrySchema,
  structuredVaultPayloadSchema,
  timestampSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { evaluatePermission } from '../src/execution/engine.js';
import { diffPolicyDefinition } from '../src/execution/policy-analysis.js';
import { resolveExecutionValue } from '../src/execution/secret-resolution.js';
import { createEmptyStructuredVaultPayload } from '../src/structured-vault-projection.js';
import {
  createProjectContext,
  createStructuredService,
  createStructuredItem,
  removeStructuredItem,
  setStructuredField,
} from '../src/structured-vault-impl.js';
import { recordItemSnapshots, restoreItemSnapshot } from '../src/item-snapshots.js';

const at = timestampSchema.parse('2026-10-28T00:00:00.000Z');
function credential() {
  let payload = createEmptyStructuredVaultPayload(
    vaultIdSchema.parse('vault_review'),
    at,
  );
  payload = createProjectContext(payload, 'project/prod', 'production', at);
  payload = createStructuredService(payload, 'project/prod', 'api', at);
  payload = createStructuredItem(payload, 'project/prod', 'api', 'deploy', at);
  return setStructuredField(payload, 'project/prod', 'api', 'deploy', {
    name: 'token',
    type: 'api-key',
    rawValue: 'snapshot-canary-before',
    now: at,
  });
}
describe('firewall extensions', () => {
  it('reports operation changes and never hides a target change in a semantic diff', () => {
    const base = permissionEntrySchema.parse({
      secret: 'github/token',
      commands: ['gh'],
    });
    const restricted = permissionEntrySchema.parse({
      ...base,
      operations: [
        { command: 'gh', args: ['issue', 'list', '--repo', 'example/first'] },
      ],
    });
    expect(diffPolicyDefinition('review', base, restricted).changes).toContainEqual(
      expect.objectContaining({ field: 'operations', impact: 'tightens' }),
    );
    expect(diffPolicyDefinition('review', restricted, base).changes).toContainEqual(
      expect.objectContaining({ field: 'operations', impact: 'widens' }),
    );
    const retargeted = permissionEntrySchema.parse({
      ...base,
      operations: [
        { command: 'gh', args: ['issue', 'list', '--repo', 'example/second'] },
      ],
    });
    expect(diffPolicyDefinition('review', restricted, retargeted)).toMatchObject({
      changed: true,
      changes: [expect.objectContaining({ field: 'operations', impact: 'changes' })],
    });
  });
  it('resolves a sensitive structured field without a reveal operation', () => {
    const payload = credential();
    expect(
      resolveExecutionValue(
        payload,
        executionReference({
          context: 'project/prod',
          service: 'api',
          item: 'deploy',
          field: 'token',
        }),
      ),
    ).toBe('snapshot-canary-before');
    expect(() => resolveExecutionValue(payload, 'deploy')).toThrow();
  });
  it('requires an entire approved operation, including its target and flags', () => {
    const entry = permissionEntrySchema.parse({
      secret: 'github/token',
      commands: ['gh'],
      operations: [
        { command: 'gh', args: ['issue', 'list', '--repo', 'example/project'] },
      ],
    });
    const context = {
      platform: process.platform,
      facts: {
        displayName: 'gh',
        sha256: undefined,
        firstArgument: 'issue',
        arguments: ['issue', 'list', '--repo', 'example/project'],
      },
      nowIso: at,
      cwdRealPath: process.cwd(),
    };
    expect(evaluatePermission(entry, context).outcome).toBe('allow');
    for (const args of [
      ['issue', 'list'],
      ['issue', 'delete', '--repo', 'example/project'],
      [...context.facts.arguments, '--web'],
    ]) {
      expect(
        evaluatePermission(entry, {
          ...context,
          facts: { ...context.facts, arguments: args },
        }),
      ).toMatchObject({ outcome: 'deny', reason: 'operation-not-allowed' });
    }
  });
  it('captures a prior item and restores its contents as a new revision', () => {
    const before = credential();
    const after = setStructuredField(before, 'project/prod', 'api', 'deploy', {
      name: 'token',
      type: 'api-key',
      rawValue: 'snapshot-canary-after',
      now: at,
    });
    const recorded = recordItemSnapshots(before, after, at);
    expect(recorded.version).toBe(2);
    expect(recorded.snapshots).toHaveLength(1);
    const snapshot = recorded.snapshots?.[0];
    expect(snapshot).toBeDefined();
    const restored = restoreItemSnapshot(
      recorded,
      'project/prod',
      'api',
      'deploy',
      snapshot!.id,
      at,
    );
    expect(
      resolveExecutionValue(
        restored,
        executionReference({
          context: 'project/prod',
          service: 'api',
          item: 'deploy',
          field: 'token',
        }),
      ),
    ).toBe('snapshot-canary-before');
    expect(restored.items.at(-1)?.revision).toBeGreaterThan(
      recorded.items.at(-1)!.revision,
    );
    expect(() =>
      restoreItemSnapshot(recorded, 'project/prod', 'api', 'deploy', 'missing', at),
    ).toThrow();
  });
  it('binds snapshots to their vault and item and removes them with a permanent deletion', () => {
    const before = credential();
    const after = setStructuredField(before, 'project/prod', 'api', 'deploy', {
      name: 'token',
      type: 'api-key',
      rawValue: 'changed',
      now: at,
    });
    const recorded = recordItemSnapshots(before, after, at);
    const snapshot = recorded.snapshots![0]!;
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...recorded,
        snapshots: [
          { ...snapshot, item: { ...snapshot.item, vaultId: 'vault_other' } },
        ],
      }).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...recorded,
        snapshots: [{ ...snapshot, item: { ...snapshot.item, id: 'item_other' } }],
      }).success,
    ).toBe(false);
    const removed = removeStructuredItem(recorded, 'project/prod', 'api', 'deploy', at);
    expect(removed.snapshots).toEqual([]);
    expect(() =>
      restoreItemSnapshot(removed, 'project/prod', 'api', 'deploy', snapshot.id, at),
    ).toThrow();
  });
  it('retains at most 100 prior versions per item without dropping the most recent snapshot', () => {
    let current = credential();
    let mostRecent = '';
    for (let index = 0; index < 103; index++) {
      const next = setStructuredField(current, 'project/prod', 'api', 'deploy', {
        name: 'token',
        type: 'api-key',
        rawValue: 'revision-' + String(index),
        now: at,
      });
      current = recordItemSnapshots(current, next, at);
      mostRecent = current.snapshots!.at(-1)!.id;
    }
    expect(current.snapshots).toHaveLength(100);
    expect(current.snapshots!.at(-1)!.id).toBe(mostRecent);
    expect(
      new Set(current.snapshots!.map((snapshot) => snapshot.item.revision)).size,
    ).toBe(100);
  });
});
