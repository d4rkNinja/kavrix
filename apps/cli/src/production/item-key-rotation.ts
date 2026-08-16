import {
  VaultMutationService,
  VaultReadSession,
  type ItemKeyRotationRequest,
} from '@kavrix/client';
import { NotFoundError, resolveNamedEntity } from '@kavrix/core';
import type { GroupPayload, ItemId, ItemPayload } from '@kavrix/schemas';

import type { CliItemKeyRotationResult } from '../contracts.js';
import type { CliItemKeyRotationRequest } from '../mutation-contracts.js';
import {
  createDefaultMutationDependencies,
  type ProductionMutationOptions,
} from './mutations.js';

/**
 * Rotates the item keys of one group's credentials.
 *
 * Names are resolved first, in a read session that is locked again before the
 * rotation starts, so the operator can address credentials the way the rest of
 * the CLI does while the rotation itself still works on opaque IDs only. An
 * unresolvable selector is refused before anything is published, because a
 * rotation that silently dropped a mistyped credential would read as if that
 * credential had been rekeyed.
 *
 * The report names the skipped credentials as well as the rotated ones: an
 * attachment-bearing credential keeps the exact key its attachment keys are
 * wrapped under, and hiding that would present a partial rotation as a complete
 * one.
 */
export async function executeProductionItemKeyRotation(
  options: ProductionMutationOptions,
  request: CliItemKeyRotationRequest,
): Promise<CliItemKeyRotationResult> {
  const { group, items } = await readGroupScope(options, request.groupQuery);
  const selection = resolveSelection(items, request.credentialQueries);
  const titles = new Map(items.map((item) => [item.id, item.title]));

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );
  const rotation: ItemKeyRotationRequest = {
    groupId: group.id,
    ...(selection === undefined ? {} : { itemIds: selection }),
  };
  const report = await service.rotateItemKeys(rotation);

  return {
    vaultId: options.vaultId,
    groupId: report.groupId,
    groupName: group.name,
    rotated: report.rotated.map((credentialId) => ({
      credentialId,
      title: titles.get(credentialId) ?? credentialId,
    })),
    skipped: report.skipped.map((skip) => ({
      credentialId: skip.itemId,
      title: titles.get(skip.itemId) ?? skip.itemId,
      reason: skip.reason,
    })),
  };
}

/**
 * Opens one group and its credentials in a single read pass.
 *
 * `listScopes` resolves the group and decrypts its items under one group key, so
 * naming credentials costs one pass instead of one read per selector.
 */
async function readGroupScope(
  options: ProductionMutationOptions,
  groupQuery: string,
): Promise<{ group: GroupPayload; items: readonly ItemPayload[] }> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const [scope] = await readSession.listScopes(groupQuery);
    if (scope === undefined) throw new NotFoundError();
    return { group: scope.group, items: scope.items };
  } finally {
    readSession.lock();
  }
}

/**
 * Maps credential selectors onto the IDs the client rotates.
 *
 * `undefined` means "every active credential in the group", which is what an
 * omitted selection asks for. Tombstones stay resolvable so a selector that
 * names one is reported as a `deleted` skip instead of as a missing credential,
 * and a selector that resolves to the same credential twice is refused by the
 * client rather than silently collapsed here.
 */
function resolveSelection(
  items: readonly ItemPayload[],
  queries: readonly string[] | undefined,
): readonly ItemId[] | undefined {
  if (queries === undefined) return undefined;
  const candidates = items.map((item) => ({
    id: item.id,
    name: item.title,
    slug: item.slug,
    aliases: item.aliases,
    itemId: item.id,
  }));
  return queries.map((query) => resolveNamedEntity(query, candidates).itemId);
}
