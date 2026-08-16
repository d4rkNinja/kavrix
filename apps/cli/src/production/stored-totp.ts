import { VaultReadSession, type VaultReadSourcePort } from '@kavrix/client';
import {
  assertTotpRevealPermitted,
  assertTotpSecretField,
  generateStoredTotpCode,
  resolveNamedEntity,
  selectTotpSecretField,
} from '@kavrix/core';
import type { VaultRootKey } from '@kavrix/crypto';
import type { FieldDefinition, FieldValue, VaultId } from '@kavrix/schemas';

import type { CliStoredTotpRequest, CliStoredTotpResult } from '../contracts.js';

export type ProductionStoredTotpOptions = Readonly<{
  source: VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
}>;

/** A field a TOTP request may resolve to, with its stored value already paired. */
interface TotpFieldCandidate {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly aliases: readonly string[];
  readonly definition: FieldDefinition;
  readonly value: FieldValue | undefined;
}

/**
 * Generate one TOTP code from a seed stored in the local encrypted vault.
 *
 * The seed is decrypted locally, used inside the core policy, and its decoded
 * bytes are wiped there before this function returns; nothing seed-derived
 * other than the code itself crosses back out. No request is made to the API,
 * because a zero-knowledge server has neither the seed nor the key that would
 * let it produce a code.
 *
 * The read session is locked in `finally` so an interrupted resolution releases
 * the unwrapped keys on the same path a successful one does.
 */
export async function executeProductionStoredTotp(
  options: ProductionStoredTotpOptions,
  request: CliStoredTotpRequest,
): Promise<CliStoredTotpResult> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let aggregate: Awaited<ReturnType<VaultReadSession['show']>>;
  try {
    aggregate = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  const candidates = totpFieldCandidates(aggregate);
  // An explicit query resolves by identity across every field, so naming a
  // non-TOTP field is refused as a wrong type rather than silently skipped and
  // reported as "no seed found".
  const resolved =
    request.fieldQuery === undefined
      ? selectTotpSecretField(candidates)
      : resolveNamedEntity(request.fieldQuery, candidates);

  assertTotpSecretField(resolved.definition);
  assertTotpRevealPermitted(resolved.definition);

  const generated = generateStoredTotpCode(
    resolved.definition,
    resolved.value,
    request.configuration,
    request.unixTimeSeconds,
  );

  return {
    groupName: aggregate.group.name,
    credentialTitle: aggregate.item.title,
    fieldLabel: resolved.definition.label,
    fieldKey: resolved.definition.stableKey,
    code: generated.code,
    remainingSeconds: generated.remainingSeconds,
    algorithm: generated.configuration.algorithm,
    digits: generated.configuration.digits,
    periodSeconds: generated.configuration.periodSeconds,
  };
}

/**
 * Pair every field a credential exposes with its stored value.
 *
 * Item fields come after template fields and shadow them by definition ID, which
 * matches how a stored item overrides its template, so a shadowed template field
 * cannot make an otherwise unique seed selection look ambiguous.
 */
function totpFieldCandidates(
  aggregate: Awaited<ReturnType<VaultReadSession['show']>>,
): readonly TotpFieldCandidate[] {
  const { item, template } = aggregate;
  const templateValues = new Map(
    item.templateValues.map((stored) => [stored.fieldId, stored]),
  );
  const itemValues = new Map(item.itemValues.map((stored) => [stored.fieldId, stored]));
  const shadowed = new Set(item.itemFields.map(({ id }) => id));

  return Object.freeze([
    ...template.fields
      .filter(({ id }) => !shadowed.has(id))
      .map((definition) =>
        candidate(definition, templateValues.get(definition.id)?.value),
      ),
    ...item.itemFields.map((definition) =>
      candidate(definition, itemValues.get(definition.id)?.value),
    ),
  ]);
}

function candidate(
  definition: FieldDefinition,
  value: FieldValue | undefined,
): TotpFieldCandidate {
  return Object.freeze<TotpFieldCandidate>({
    id: definition.id,
    name: definition.label,
    slug: definition.stableKey,
    aliases: Object.freeze([]),
    definition,
    value,
  });
}
