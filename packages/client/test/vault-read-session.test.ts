import { describe, expect, it } from 'vitest';

import {
  AmbiguousNameError,
  CryptoAuthenticationError,
  NotFoundError,
  VaultLockedError,
} from '@kavrix/core';
import { cloneSecretKey } from '@kavrix/crypto';

import {
  MAX_VAULT_GROUPS,
  VaultReadSession,
  VaultSessionConcurrencyError,
} from '../src/index.js';
import { MemoryReadSource, encryptedFixture, mutateCiphertext } from './fixtures.js';

describe('VaultReadSession', () => {
  it('owns a root-key copy and resolves exact ID, name, slug, alias, then prefix', async () => {
    const fixture = await encryptedFixture();
    const source = new MemoryReadSource(fixture);
    const session = new VaultReadSession(source, fixture.vaultId);
    const supplied = cloneSecretKey(fixture.rootKey);
    await session.unlock(supplied);
    supplied.fill(0);

    await expect(session.showGroup('Production')).resolves.toMatchObject({
      id: 'group.1',
    });
    await expect(session.showGroup('group-1')).resolves.toMatchObject({
      id: 'group.1',
    });
    await expect(session.showGroup('g1')).resolves.toMatchObject({ id: 'group.1' });
    await expect(session.showGroup('group.1')).resolves.toMatchObject({
      id: 'group.1',
    });
    await expect(session.showGroup('Prod')).resolves.toMatchObject({ id: 'group.1' });
    await expect(session.show('Production', 'Pri')).resolves.toMatchObject({
      item: { id: 'item.1.1', title: 'Primary' },
      template: { id: 'template.1', name: 'Custom' },
    });
    expect(await session.listGroups()).toHaveLength(1);
    expect(await session.listItems('Production')).toHaveLength(1);
    await expect(session.unlock(fixture.rootKey)).rejects.toBeInstanceOf(
      VaultSessionConcurrencyError,
    );
  });

  it('bounds named group enumeration before resolving metadata', async () => {
    const fixture = await encryptedFixture({
      groupNames: Array.from(
        { length: MAX_VAULT_GROUPS + 1 },
        (_, index) => `Group ${String(index)}`,
      ),
      itemTitles: [],
    });
    const session = new VaultReadSession(
      new MemoryReadSource(fixture),
      fixture.vaultId,
    );
    await session.unlock(fixture.rootKey);
    await expect(session.showGroup('not-present')).rejects.toBeInstanceOf(
      CryptoAuthenticationError,
    );
  });

  it('falls back to name resolution when an opaque-looking item name is another group ID', async () => {
    const fixture = await encryptedFixture({
      groupNames: ['First', 'Second'],
      itemTitles: ['item.2.1'],
    });
    const source = new MemoryReadSource(fixture);
    const session = new VaultReadSession(source, fixture.vaultId);
    await session.unlock(fixture.rootKey);

    await expect(session.show('group.1', 'item.2.1')).resolves.toMatchObject({
      group: { id: 'group.1' },
      item: { id: 'item.1.1', title: 'item.2.1' },
    });
    expect(source.calls).toMatchObject({
      getGroup: 1,
      getItem: 1,
      listGroups: 1,
      listItems: 1,
    });
  });

  it('rejects missing and malformed vault metadata during unlock', async () => {
    const fixture = await encryptedFixture();
    const missing = new MemoryReadSource(fixture);
    missing.vault = null;
    await expect(
      new VaultReadSession(missing, fixture.vaultId).unlock(fixture.rootKey),
    ).rejects.toBeInstanceOf(NotFoundError);

    const malformed = new MemoryReadSource(fixture);
    malformed.vault = { ...fixture.vault, schemaVersion: 0 } as never;
    await expect(
      new VaultReadSession(malformed, fixture.vaultId).unlock(fixture.rootKey),
    ).rejects.toBeInstanceOf(CryptoAuthenticationError);
  });

  it('rejects missing, ambiguous, duplicate, tombstoned, and stale records', async () => {
    const ambiguous = await encryptedFixture({
      itemTitles: ['Duplicate', 'Duplicate'],
    });
    const ambiguousSession = new VaultReadSession(
      new MemoryReadSource(ambiguous),
      ambiguous.vaultId,
    );
    await ambiguousSession.unlock(ambiguous.rootKey);
    await expect(
      ambiguousSession.show('Production', 'Duplicate'),
    ).rejects.toBeInstanceOf(AmbiguousNameError);
    await expect(ambiguousSession.show('Production', 'missing')).rejects.toBeInstanceOf(
      NotFoundError,
    );

    const duplicate = await encryptedFixture();
    const duplicateSource = new MemoryReadSource(duplicate);
    const duplicateGroup = required(duplicate.groups[0]);
    duplicateSource.groups = [duplicateGroup, duplicateGroup];
    const duplicateSession = new VaultReadSession(duplicateSource, duplicate.vaultId);
    await duplicateSession.unlock(duplicate.rootKey);
    await expect(duplicateSession.listGroups()).rejects.toBeInstanceOf(
      CryptoAuthenticationError,
    );

    const tombstoned = await encryptedFixture();
    const tombstonedSource = new MemoryReadSource(tombstoned);
    tombstonedSource.groups = [
      {
        ...required(tombstoned.groups[0]),
        tombstonedAt: '2026-08-10T00:00:00.000Z',
      },
    ];
    const tombstonedSession = new VaultReadSession(
      tombstonedSource,
      tombstoned.vaultId,
    );
    await tombstonedSession.unlock(tombstoned.rootKey);
    await expect(tombstonedSession.listGroups()).rejects.toBeInstanceOf(
      CryptoAuthenticationError,
    );

    const stale = await encryptedFixture({ recordKeyVersion: 2 });
    const staleSource = new MemoryReadSource(stale);
    const staleSession = new VaultReadSession(staleSource, stale.vaultId);
    await staleSession.unlock(stale.rootKey);
    await expect(staleSession.listGroups()).rejects.toBeInstanceOf(
      CryptoAuthenticationError,
    );
  });

  it('fails closed for tampered, swapped, noncanonical, and cross-template data', async () => {
    const tampered = await encryptedFixture();
    const tamperedSource = new MemoryReadSource(tampered);
    const tamperedGroup = required(tampered.groupPayloads[0]);
    const tamperedRecord = required(tampered.items.get(tamperedGroup.id)?.[0]);
    tamperedSource.items = new Map([
      [tamperedGroup.id, [mutateCiphertext(tamperedRecord)]],
    ]);
    const tamperedSession = new VaultReadSession(tamperedSource, tampered.vaultId);
    await tamperedSession.unlock(tampered.rootKey);
    await expect(tamperedSession.listItems('Production')).rejects.toBeInstanceOf(
      CryptoAuthenticationError,
    );

    const swapped = await encryptedFixture({ groupNames: ['First', 'Second'] });
    const swappedSource = new MemoryReadSource(swapped);
    const firstGroup = required(swapped.groups[0]);
    const secondGroup = required(swapped.groups[1]);
    swappedSource.groups = [
      {
        ...firstGroup,
        encryptedPayload: secondGroup.encryptedPayload,
      },
    ];
    const swappedSession = new VaultReadSession(swappedSource, swapped.vaultId);
    await swappedSession.unlock(swapped.rootKey);
    await expect(swappedSession.listGroups()).rejects.toBeInstanceOf(
      CryptoAuthenticationError,
    );

    const noncanonical = await encryptedFixture({ nonCanonicalItem: true });
    const noncanonicalSession = new VaultReadSession(
      new MemoryReadSource(noncanonical),
      noncanonical.vaultId,
    );
    await noncanonicalSession.unlock(noncanonical.rootKey);
    await expect(noncanonicalSession.listItems('Production')).rejects.toBeInstanceOf(
      CryptoAuthenticationError,
    );

    const wrongTemplate = await encryptedFixture({
      itemTemplateId: 'template.unrelated',
    });
    const wrongTemplateSession = new VaultReadSession(
      new MemoryReadSource(wrongTemplate),
      wrongTemplate.vaultId,
    );
    await wrongTemplateSession.unlock(wrongTemplate.rootKey);
    await expect(
      wrongTemplateSession.show('Production', 'Primary'),
    ).rejects.toBeInstanceOf(CryptoAuthenticationError);
  });

  it('locks atomically against in-flight and concurrent reads', async () => {
    const fixture = await encryptedFixture();
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const source = new MemoryReadSource(fixture);
    source.listGroups = async function* (vaultId) {
      await gate;
      for (const group of this.groups) {
        if (group.vaultId === vaultId) yield group;
      }
    };
    const session = new VaultReadSession(source, fixture.vaultId);
    await session.unlock(fixture.rootKey);
    const pending = session.listGroups();
    await expect(session.showGroup('Production')).rejects.toBeInstanceOf(
      VaultSessionConcurrencyError,
    );
    session.lock();
    release?.();
    await expect(pending).rejects.toBeInstanceOf(VaultLockedError);
    expect(session.locked).toBe(true);
    await expect(session.listGroups()).rejects.toBeInstanceOf(VaultLockedError);
  });

  it('does not retain plaintext in errors or enumerable session inspection', async () => {
    const canary = 'PLAINTEXT-CANARY-CLIENT-17d83';
    const fixture = await encryptedFixture({ plaintextCanary: canary });
    const source = new MemoryReadSource(fixture);
    const canaryGroup = required(fixture.groupPayloads[0]);
    const canaryRecord = required(fixture.items.get(canaryGroup.id)?.[0]);
    source.items = new Map([[canaryGroup.id, [mutateCiphertext(canaryRecord)]]]);
    const session = new VaultReadSession(source, fixture.vaultId);
    await session.unlock(fixture.rootKey);
    const error = await session
      .show('Production', 'Primary')
      .catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(CryptoAuthenticationError);
    expect(JSON.stringify(error)).not.toContain(canary);
    expect(JSON.stringify(session)).not.toContain(canary);
    expect(String(error)).not.toContain(canary);
    session.lock();
  });
});

function required<TValue>(value: TValue | undefined): TValue {
  if (value === undefined) throw new Error('The test fixture is incomplete.');
  return value;
}
