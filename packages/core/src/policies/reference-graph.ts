import type {
  ActiveFieldValue,
  FieldDefinition,
  GroupPayload,
  ItemId,
  ItemPayload,
} from '@kavrix/schemas';

import { ValidationError } from '../errors.js';

/** Deepest outward walk a caller may request, so a dense graph cannot be turned into unbounded work. */
export const MAX_REFERENCE_TRAVERSAL_DEPTH = 16;
/** Depth used when a caller states no preference: the credential's own references only. */
export const DEFAULT_REFERENCE_TRAVERSAL_DEPTH = 1;
/** Hard ceiling on reported nodes, independent of the requested depth. */
export const MAX_REFERENCE_TRAVERSAL_NODES = 500;

/**
 * How a referenced credential resolved inside the unlocked vault.
 *
 * `missing` is the canonical outcome for a deleted target: a tombstoned record is
 * excluded from every read, so the relation survives with nothing behind it and
 * has to be reported rather than dropped. `archived` is deliberately distinct
 * from both — archiving retires a credential without breaking the relation, so
 * collapsing it into either neighbour would misstate the target's state.
 */
export type ReferenceTargetState = 'active' | 'archived' | 'missing';

/**
 * A stored field value that carries a reference.
 *
 * Only the field's identity is reported. The value itself is the opaque target
 * ID that is already named by the reference, so nothing here can disclose a
 * field value that `reveal` would refuse.
 */
export type ReferenceBinding = Readonly<{
  fieldKey: string;
  fieldLabel: string;
  scope: 'template' | 'item';
  /** Present when the reference is one element of a repeatable field. */
  elementId?: string;
}>;

/** One outbound relation of a credential, resolved locally. */
export type CredentialReference = Readonly<{
  targetId: ItemId;
  state: ReferenceTargetState;
  /** Present only when the target resolved; absent for a missing target. */
  groupId?: GroupPayload['id'];
  groupName?: string;
  title?: string;
  /**
   * Fields whose stored value points at this target.
   *
   * Empty means the relation is declared on the credential but no field binds
   * it. That is a valid canonical state — `relatedItemIds` is the authoritative
   * relation list and a field reference is required to appear in it, not the
   * other way round — so it is reported instead of being treated as an error.
   */
  bindings: readonly ReferenceBinding[];
  /** The target declares this credential in its own relation list. */
  reciprocal: boolean;
}>;

/** One credential reached by an outward walk. */
export type ReferenceGraphNode = Readonly<{
  /** Distance from the root in edges; the root itself is 0. */
  depth: number;
  credentialId: ItemId;
  state: ReferenceTargetState;
  groupId?: GroupPayload['id'];
  groupName?: string;
  title?: string;
  /** The credential this node was reached from; absent for the root. */
  parentId?: ItemId;
  bindings: readonly ReferenceBinding[];
  /**
   * This credential was already reported, so the walk stopped here instead of
   * expanding it a second time.
   */
  revisit: boolean;
  /**
   * The edge that reached this node closes a cycle: the target is the root or an
   * ancestor of this node on its own path back to the root.
   */
  cycle: boolean;
}>;

export type ReferenceGraphResult = Readonly<{
  rootId: ItemId;
  /** Breadth-first, root first, then each depth in the order its edges are declared. */
  nodes: readonly ReferenceGraphNode[];
  /** Nodes whose edge closed a cycle. */
  cycleCount: number;
  /** Nodes whose target did not resolve in the unlocked vault. */
  missingCount: number;
  /** The node ceiling stopped the walk before the requested depth was exhausted. */
  truncated: boolean;
  /** Depth actually walked, which is the requested depth unless truncation stopped it earlier. */
  reachedDepth: number;
}>;

/** One group and the credentials read from it, already decrypted in memory. */
export type ReferenceScope = Readonly<{
  group: GroupPayload;
  credentials: readonly ItemPayload[];
}>;

export type ReferenceTraversalOptions = Readonly<{
  maxDepth?: number;
}>;

/**
 * A credential located in the unlocked vault together with its owning group.
 *
 * Built once per invocation so that resolving a relation is a map lookup rather
 * than a rescan: a credential with many relations, walked to depth N, would
 * otherwise cost a full pass over the vault per edge.
 */
type ReferenceIndex = ReadonlyMap<
  string,
  Readonly<{ group: GroupPayload; credential: ItemPayload }>
>;

function buildIndex(scopes: readonly ReferenceScope[]): ReferenceIndex {
  const index = new Map<
    string,
    Readonly<{ group: GroupPayload; credential: ItemPayload }>
  >();
  for (const { group, credentials } of scopes) {
    for (const credential of credentials) {
      index.set(credential.id, { group, credential });
    }
  }
  return index;
}

function targetState(credential: ItemPayload): ReferenceTargetState {
  return credential.archivedAt === undefined ? 'active' : 'archived';
}

/**
 * Reports the credential's outbound relations, each resolved locally.
 *
 * Resolution is pure and in-memory: the caller has already decrypted everything,
 * so no name, no title, and no relation ever leaves the process. A target that
 * does not resolve is reported as `missing` rather than omitted, because a
 * silently shortened list would read as "no such relation" when the truth is
 * "the relation outlived its target".
 */
export function resolveCredentialReferences(
  scopes: readonly ReferenceScope[],
  credentialId: ItemId,
): readonly CredentialReference[] {
  const index = buildIndex(scopes);
  const located = index.get(credentialId);
  if (located === undefined) {
    throw new ValidationError('The credential is not present in the unlocked vault.');
  }
  return referencesOf(index, located.credential);
}

function referencesOf(
  index: ReferenceIndex,
  credential: ItemPayload,
): readonly CredentialReference[] {
  const bindings = bindingsByTarget(credential);
  return Object.freeze(
    credential.relatedItemIds.map((targetId) => {
      const target = index.get(targetId);
      const reciprocal =
        target?.credential.relatedItemIds.some((back) => back === credential.id) ===
        true;
      return Object.freeze({
        targetId,
        state: target === undefined ? 'missing' : targetState(target.credential),
        ...(target === undefined
          ? {}
          : {
              groupId: target.group.id,
              groupName: target.group.name,
              title: target.credential.title,
            }),
        bindings: Object.freeze(bindings.get(targetId) ?? []),
        reciprocal,
      } satisfies CredentialReference);
    }),
  );
}

/**
 * Groups a credential's reference-carrying field values by the target they name.
 *
 * Both value collections are walked with their own definition list, because a
 * template field and an item-only field can hold a reference and the scope has to
 * survive into the report: an operator removing a reference needs to know which
 * of the two a field came from.
 */
function bindingsByTarget(
  credential: ItemPayload,
): ReadonlyMap<string, readonly ReferenceBinding[]> {
  const byTarget = new Map<string, ReferenceBinding[]>();
  const definitions = new Map(
    credential.itemFields.map((definition) => [definition.id, definition] as const),
  );
  const collections = [
    { scope: 'template' as const, values: credential.templateValues },
    { scope: 'item' as const, values: credential.itemValues },
  ];
  for (const { scope, values } of collections) {
    for (const stored of values) {
      const definition = definitions.get(stored.fieldId);
      for (const found of referencesInValue(stored.value)) {
        const list = byTarget.get(found.itemId) ?? [];
        list.push(
          Object.freeze({
            fieldKey: stored.stableKey,
            fieldLabel: definition?.label ?? stored.stableKey,
            scope,
            ...(found.elementId === undefined ? {} : { elementId: found.elementId }),
          }),
        );
        byTarget.set(found.itemId, list);
      }
    }
  }
  return byTarget;
}

/** Every item reference inside one stored value, with its element ID when repeatable. */
function referencesInValue(
  value: ActiveFieldValue | Readonly<{ state: 'orphaned' }>,
): readonly Readonly<{ itemId: string; elementId?: string }>[] {
  if (value.state !== 'present') return [];
  if (value.content.cardinality === 'single') {
    const scalar = value.content.value;
    return scalar.kind === 'item-reference' ? [{ itemId: scalar.itemId }] : [];
  }
  const found: Readonly<{ itemId: string; elementId?: string }>[] = [];
  for (const element of value.content.elements) {
    if (element.value.kind === 'item-reference') {
      found.push({ itemId: element.value.itemId, elementId: element.id });
    }
  }
  return found;
}

/**
 * Walks outward from one credential, stopping at every repeat.
 *
 * The walk is breadth-first and each credential is expanded at most once, so a
 * cycle cannot make it run forever no matter how the relations are arranged. A
 * repeated target is still *reported*, marked `revisit`, and marked `cycle` when
 * it is the root or an ancestor of the node that reached it — a traversal that
 * silently pruned repeats would hide exactly the structure the operator is
 * looking for.
 */
export function traverseReferenceGraph(
  scopes: readonly ReferenceScope[],
  rootId: ItemId,
  options: ReferenceTraversalOptions = {},
): ReferenceGraphResult {
  const maxDepth = resolveDepth(options.maxDepth);
  const index = buildIndex(scopes);
  const root = index.get(rootId);
  if (root === undefined) {
    throw new ValidationError('The credential is not present in the unlocked vault.');
  }

  const rootNode: ReferenceGraphNode = Object.freeze({
    depth: 0,
    credentialId: rootId,
    state: targetState(root.credential),
    groupId: root.group.id,
    groupName: root.group.name,
    title: root.credential.title,
    bindings: Object.freeze([]),
    revisit: false,
    cycle: false,
  });

  const nodes: ReferenceGraphNode[] = [rootNode];
  // Ancestors are tracked per node rather than globally: a node repeated on a
  // sibling branch is a shared target, while a node repeated on its own path
  // back to the root is a cycle, and the two must not be reported alike.
  const ancestors = new Map<string, ReadonlySet<string>>([
    [rootId, new Set<string>([rootId])],
  ]);
  const expanded = new Set<string>([rootId]);
  let frontier: readonly Readonly<{ id: ItemId; credential: ItemPayload }>[] = [
    { id: rootId, credential: root.credential },
  ];
  let cycleCount = 0;
  let missingCount = 0;
  let truncated = false;
  let reachedDepth = 0;

  for (let depth = 1; depth <= maxDepth && frontier.length > 0 && !truncated; depth++) {
    const next: Readonly<{ id: ItemId; credential: ItemPayload }>[] = [];
    for (const parent of frontier) {
      for (const reference of referencesOf(index, parent.credential)) {
        if (nodes.length >= MAX_REFERENCE_TRAVERSAL_NODES) {
          truncated = true;
          break;
        }
        const path = ancestors.get(parent.id) ?? new Set<string>();
        const cycle = path.has(reference.targetId);
        const revisit = cycle || expanded.has(reference.targetId);
        if (cycle) cycleCount += 1;
        if (reference.state === 'missing') missingCount += 1;
        nodes.push(
          Object.freeze({
            depth,
            credentialId: reference.targetId,
            state: reference.state,
            ...(reference.groupId === undefined
              ? {}
              : {
                  groupId: reference.groupId,
                  groupName: reference.groupName,
                  title: reference.title,
                }),
            parentId: parent.id,
            bindings: reference.bindings,
            revisit,
            cycle,
          } satisfies ReferenceGraphNode),
        );
        reachedDepth = depth;
        if (revisit || reference.state === 'missing') continue;
        const target = index.get(reference.targetId);
        if (target === undefined) continue;
        expanded.add(reference.targetId);
        ancestors.set(
          reference.targetId,
          new Set<string>([...path, reference.targetId]),
        );
        next.push({ id: reference.targetId, credential: target.credential });
      }
      if (truncated) break;
    }
    frontier = next;
  }

  return Object.freeze({
    rootId,
    nodes: Object.freeze(nodes),
    cycleCount,
    missingCount,
    truncated,
    reachedDepth,
  });
}

function resolveDepth(requested: number | undefined): number {
  if (requested === undefined) return DEFAULT_REFERENCE_TRAVERSAL_DEPTH;
  if (
    !Number.isInteger(requested) ||
    requested < 1 ||
    requested > MAX_REFERENCE_TRAVERSAL_DEPTH
  ) {
    throw new ValidationError(
      `A traversal depth must be an integer between 1 and ${String(MAX_REFERENCE_TRAVERSAL_DEPTH)}.`,
    );
  }
  return requested;
}

/**
 * Reports whether adding an edge would close a cycle, and along which path.
 *
 * A bidirectional relation is legitimate, so this is a disclosure and not a
 * prohibition: the caller decides whether to proceed, and the returned path
 * exists so the decision can be stated in terms of the credentials involved
 * rather than as an opaque warning.
 */
export function findReferencePath(
  scopes: readonly ReferenceScope[],
  fromId: ItemId,
  toId: ItemId,
): readonly ItemId[] | undefined {
  const index = buildIndex(scopes);
  if (!index.has(fromId)) {
    throw new ValidationError('The credential is not present in the unlocked vault.');
  }
  if (fromId === toId) return [fromId];

  const queue: ItemId[] = [fromId];
  const cameFrom = new Map<string, ItemId>();
  const seen = new Set<string>([fromId]);
  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined) break;
    const located = index.get(current);
    if (located === undefined) continue;
    for (const targetId of located.credential.relatedItemIds) {
      if (seen.has(targetId)) continue;
      seen.add(targetId);
      cameFrom.set(targetId, current);
      if (targetId === toId) {
        const path: ItemId[] = [targetId];
        let step = current;
        while (step !== fromId) {
          path.unshift(step);
          const previous = cameFrom.get(step);
          if (previous === undefined) break;
          step = previous;
        }
        path.unshift(fromId);
        return Object.freeze(path);
      }
      queue.push(targetId);
    }
  }
  return undefined;
}

/**
 * Reports whether a field definition may hold an item reference.
 *
 * Kept here rather than at the call site so the CLI, a future API surface, and a
 * future UI cannot disagree about what a reference field is.
 */
export function isItemReferenceField(definition: FieldDefinition): boolean {
  return definition.type === 'item-reference';
}
