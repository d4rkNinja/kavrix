import { Readable, Writable } from 'node:stream';

import { groupIdSchema, itemIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;

type ListPort = NonNullable<CliUseCasePorts['listReferences']>;
type ListRequest = Parameters<ListPort>[0];
type ListResult = Awaited<ReturnType<ListPort>>;
type AddPort = NonNullable<CliUseCasePorts['addReference']>;
type AddRequest = Parameters<AddPort>[0];
type AddResult = Awaited<ReturnType<AddPort>>;
type RemovePort = NonNullable<CliUseCasePorts['removeReference']>;
type RemoveRequest = Parameters<RemovePort>[0];
type RemoveResult = Awaited<ReturnType<RemovePort>>;

type GraphNode = ListResult['graph']['nodes'][number];

function writable(): MemoryWritable {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      content += Buffer.from(chunk).toString('utf8');
      callback();
    },
  });
  return { stream, value: () => content };
}

function useCases(overrides: Partial<CliUseCasePorts>): CliUseCasePorts {
  const unexpected = (): Promise<never> => Promise.reject(new Error('Unexpected call'));
  return {
    status: unexpected,
    lock: unexpected,
    show: unexpected,
    copy: unexpected,
    listInvitePage: unexpected,
    revokeInvite: unexpected,
    joinInvite: unexpected,
    ...overrides,
  };
}

async function execute(
  arguments_: readonly string[],
  portsOverrides: Partial<CliUseCasePorts> = {},
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const stdout = writable();
  const stderr = writable();
  const dependencies: CliDependencies = {
    ports: useCases(portsOverrides),
    secrets: {
      read: () => Promise.reject(new Error('secrets unneeded')),
      readBatch: () => Promise.reject(new Error('secrets unneeded')),
    },
    runtime: {
      stdin: Readable.from([]),
      stdout: stdout.stream,
      stderr: stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  return { exitCode, stdout: stdout.value(), stderr: stderr.value() };
}

/** A port that answers with one result and records every request it received. */
function capturing<TRequest, TResult>(
  result: TResult,
): Readonly<{
  port: (request: TRequest) => Promise<TResult>;
  calls: () => readonly TRequest[];
}> {
  const calls: TRequest[] = [];
  const port = vi.fn((request: TRequest) => {
    calls.push(request);
    return Promise.resolve(result);
  });
  return { port, calls: () => calls };
}

const VAULT_ID = vaultIdSchema.parse('vault.1');
const GROUP_ID = groupIdSchema.parse('group.1');
const OTHER_GROUP_ID = groupIdSchema.parse('group.2');
const ROOT_ID = itemIdSchema.parse('item.101');
const TARGET_ID = itemIdSchema.parse('item.102');
const DEEP_ID = itemIdSchema.parse('item.103');

/** Built from code points so no raw control byte is stored in this file. */
const ESCAPE = String.fromCharCode(0x1b);
const BELL = String.fromCharCode(0x07);
const REPLACEMENT = String.fromCharCode(0xff_fd);

function node(
  overrides: Partial<GraphNode> & Pick<GraphNode, 'credentialId'>,
): GraphNode {
  return {
    depth: 1,
    state: 'active',
    groupId: GROUP_ID,
    groupName: 'Engineering',
    bindings: [],
    revisit: false,
    cycle: false,
    ...overrides,
  };
}

/**
 * A target that no longer resolves.
 *
 * Built separately rather than by overriding the group keys with `undefined`,
 * because the contract omits them for a missing target instead of carrying them
 * as empty — which is the distinction these tests exist to hold.
 */
function missingNode(
  credentialId: GraphNode['credentialId'],
  parentId: GraphNode['credentialId'],
): GraphNode {
  return {
    depth: 1,
    credentialId,
    state: 'missing',
    parentId,
    bindings: [],
    revisit: false,
    cycle: false,
  };
}

function listResult(
  nodes: readonly GraphNode[],
  overrides: Partial<ListResult['graph']> = {},
  requestedDepth = 1,
): ListResult {
  return {
    vaultId: VAULT_ID,
    requestedDepth,
    graph: {
      rootId: ROOT_ID,
      nodes,
      cycleCount: 0,
      missingCount: 0,
      truncated: false,
      reachedDepth: 1,
      ...overrides,
    },
  };
}

const ROOT_NODE = node({
  credentialId: ROOT_ID,
  depth: 0,
  title: 'Primary DB',
});

function addResult(overrides: Partial<AddResult> = {}): AddResult {
  return {
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    credentialId: ROOT_ID,
    title: 'Primary DB',
    fieldKey: 'depends_on',
    fieldLabel: 'Depends on',
    targetId: TARGET_ID,
    targetTitle: 'Bastion Host',
    targetGroupId: GROUP_ID,
    targetGroupName: 'Engineering',
    alreadyPresent: false,
    previousRevision: 4,
    revision: 5,
    ...overrides,
  };
}

function removeResult(overrides: Partial<RemoveResult> = {}): RemoveResult {
  return {
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    credentialId: ROOT_ID,
    title: 'Primary DB',
    fieldKey: 'depends_on',
    fieldLabel: 'Depends on',
    targetId: TARGET_ID,
    targetTitle: 'Bastion Host',
    relationRemoved: true,
    previousRevision: 4,
    revision: 5,
    ...overrides,
  };
}

/**
 * A removal whose target no longer resolves, so the contract omits `targetTitle`
 * rather than carrying an empty one.
 */
function unresolvedRemoveResult(targetId: string): RemoveResult {
  return {
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    credentialId: ROOT_ID,
    title: 'Primary DB',
    fieldKey: 'depends_on',
    fieldLabel: 'Depends on',
    targetId,
    relationRemoved: true,
    previousRevision: 4,
    revision: 5,
  };
}

describe('CLI reference list command', () => {
  it('walks one level by default and names every binding that reaches a target', async () => {
    const list = capturing<ListRequest, ListResult>(
      listResult([
        ROOT_NODE,
        node({
          credentialId: TARGET_ID,
          title: 'Bastion Host',
          parentId: ROOT_ID,
          bindings: [
            { fieldKey: 'depends_on', fieldLabel: 'Depends on', scope: 'template' },
            {
              fieldKey: 'upstream',
              fieldLabel: 'Upstream',
              scope: 'item',
              elementId: 'element.ab12',
            },
          ],
        }),
      ]),
    );

    const result = await execute(['reference', 'list', 'Engineering', 'Primary DB'], {
      listReferences: list.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    // An omitted --depth must stay omitted rather than becoming a guessed
    // number, so the core policy applies its own documented default.
    expect(list.calls()).toEqual([
      { groupQuery: 'Engineering', credentialQuery: 'Primary DB' },
    ]);
    expect(result.stdout).toContain('References of Primary DB (item.101) to depth 1:');
    expect(result.stdout).toContain('- Bastion Host (item.102)');
    expect(result.stdout).toContain('Group: Engineering');
    expect(result.stdout).toContain('Field: Depends on (depends_on, template)');
    expect(result.stdout).toContain(
      'Field: Upstream (upstream, item, element element.ab12)',
    );
    expect(result.stdout).toContain(
      'Walked 1 level(s): 1 reference(s), 0 cycle(s), 0 missing target(s).',
    );
  });

  it('forwards an explicit depth and indents each level of the chain', async () => {
    const list = capturing<ListRequest, ListResult>(
      listResult(
        [
          ROOT_NODE,
          node({ credentialId: TARGET_ID, title: 'Bastion Host', parentId: ROOT_ID }),
          node({
            credentialId: DEEP_ID,
            title: 'Root CA',
            depth: 2,
            parentId: TARGET_ID,
            groupId: OTHER_GROUP_ID,
            groupName: 'Infrastructure',
          }),
        ],
        { reachedDepth: 2 },
        3,
      ),
    );

    const result = await execute(
      ['reference', 'list', 'Engineering', 'Primary DB', '--depth', '3'],
      { listReferences: list.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(list.calls()).toEqual([
      { groupQuery: 'Engineering', credentialQuery: 'Primary DB', depth: 3 },
    ]);
    expect(result.stdout).toContain('to depth 3:');
    // Depth is what makes a chain readable, so the deeper node is indented
    // further than the one that reached it.
    expect(result.stdout).toContain('  - Bastion Host (item.102)');
    expect(result.stdout).toContain('    - Root CA (item.103)');
    expect(result.stdout).toContain('Group: Infrastructure');
    expect(result.stdout).toContain('Walked 2 level(s)');
  });

  it('labels a cycle, a repeat, an archived target, and a missing target', async () => {
    const list = capturing<ListRequest, ListResult>(
      listResult(
        [
          ROOT_NODE,
          node({
            credentialId: TARGET_ID,
            title: 'Bastion Host',
            parentId: ROOT_ID,
            cycle: true,
            revisit: true,
          }),
          node({
            credentialId: DEEP_ID,
            title: 'Retired Router',
            parentId: ROOT_ID,
            state: 'archived',
          }),
          missingNode(itemIdSchema.parse('item.104'), ROOT_ID),
          node({
            credentialId: itemIdSchema.parse('item.105'),
            title: 'Shared Secret Store',
            parentId: ROOT_ID,
            revisit: true,
          }),
        ],
        { cycleCount: 1, missingCount: 1 },
      ),
    );

    const result = await execute(['reference', 'list', 'Engineering', 'Primary DB'], {
      listReferences: list.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    // Each of these is a different fact about the reference set, so none of
    // them may be rendered as any of the others.
    expect(result.stdout).toContain('- Bastion Host (item.102) [cycle]');
    expect(result.stdout).toContain('- Retired Router (item.103) [archived]');
    expect(result.stdout).toContain('- (unresolved) (item.104) [missing]');
    expect(result.stdout).toContain(
      '- Shared Secret Store (item.105) [already listed]',
    );
    expect(result.stdout).toContain(
      'Walked 1 level(s): 4 reference(s), 1 cycle(s), 1 missing target(s).',
    );
    // A relation with no field behind it is still a relation, and saying so
    // is what tells an operator where to look.
    expect(result.stdout).toContain(
      'Field: (none; the relation is declared without a field binding it)',
    );
  });

  it('reports a truncated walk instead of presenting it as complete', async () => {
    const list = capturing<ListRequest, ListResult>(
      listResult(
        [ROOT_NODE, node({ credentialId: TARGET_ID, title: 'Bastion Host' })],
        {
          truncated: true,
        },
      ),
    );

    const result = await execute(['reference', 'list', 'Engineering', 'Primary DB'], {
      listReferences: list.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain(
      'The walk stopped at the node ceiling, so the reference set is larger than shown.',
    );
  });

  it('says a credential has no references rather than printing an empty list', async () => {
    const list = capturing<ListRequest, ListResult>(listResult([ROOT_NODE]));

    const result = await execute(['reference', 'list', 'Engineering', 'Primary DB'], {
      listReferences: list.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('(none)');
    expect(result.stdout).toContain('0 reference(s)');
  });

  it('refuses a blank, hostile, or out-of-range walk before opening the vault', async () => {
    const list = capturing<ListRequest, ListResult>(listResult([ROOT_NODE]));

    for (const argv of [
      ['reference', 'list', '   ', 'Primary DB'],
      ['reference', 'list', 'Engineering', '  '],
      ['reference', 'list', `Engineering${ESCAPE}[31m`, 'Primary DB'],
      ['reference', 'list', 'Engineering', 'Primary DB', '--depth', '0'],
      ['reference', 'list', 'Engineering', 'Primary DB', '--depth', '17'],
      ['reference', 'list', 'Engineering', 'Primary DB', '--depth', 'deep'],
      ['reference', 'list', 'Engineering', 'Primary DB', '--depth', '-1'],
      ['reference', 'list', 'Engineering', 'Primary DB', '--depth', '1.5'],
    ]) {
      const result = await execute(argv, { listReferences: list.port });
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
    }
    // A refused walk must not have reached the vault at all.
    expect(list.calls()).toHaveLength(0);
  });

  it('neutralizes hostile titles and invents nothing for a missing target', async () => {
    const hostile = listResult([
      node({
        credentialId: ROOT_ID,
        depth: 0,
        title: `Primary${ESCAPE}]0;pwned${BELL}`,
      }),
      node({
        credentialId: TARGET_ID,
        title: `Bastion${ESCAPE}[2K`,
        groupName: `Engineering${ESCAPE}[31m`,
        parentId: ROOT_ID,
        bindings: [
          {
            fieldKey: 'depends_on',
            fieldLabel: `Depends${ESCAPE}[1m`,
            scope: 'template',
          },
        ],
      }),
      missingNode(DEEP_ID, ROOT_ID),
    ]);

    const text = await execute(['reference', 'list', 'Engineering', 'Primary DB'], {
      listReferences: capturing<ListRequest, ListResult>(hostile).port,
    });
    const json = await execute(
      ['reference', 'list', 'Engineering', 'Primary DB', '--json'],
      { listReferences: capturing<ListRequest, ListResult>(hostile).port },
    );

    expect(text.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(text.stdout).not.toContain(ESCAPE);
    expect(text.stdout).not.toContain(BELL);
    expect(text.stdout).toContain(REPLACEMENT);

    expect(json.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(json.stdout).not.toContain(ESCAPE);
    expect(json.stdout).not.toContain(BELL);
    const parsed = JSON.parse(json.stdout) as ListResult;
    expect(parsed.graph.nodes[1]?.title).toContain(REPLACEMENT);
    expect(parsed.graph.nodes[1]?.bindings[0]?.fieldLabel).toContain(REPLACEMENT);
    // A target that is gone has no title and no group, and the JSON must omit
    // those keys rather than emit a placeholder a script would read as real.
    expect(parsed.graph.nodes[2]).not.toHaveProperty('title');
    expect(parsed.graph.nodes[2]).not.toHaveProperty('groupName');
    expect(parsed.graph.nodes[2]?.state).toBe('missing');
  });

  it('reports an unconfigured adapter as unavailable rather than crashing', async () => {
    const result = await execute(['reference', 'list', 'Engineering', 'Primary DB']);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('reference list is unavailable');
    expect(result.stdout).toBe('');
  });
});

describe('CLI reference add command', () => {
  it('records a reference and names both endpoints with the revision it moved', async () => {
    const add = capturing<AddRequest, AddResult>(addResult());

    const result = await execute(
      ['reference', 'add', 'Engineering', 'Primary DB', 'depends_on', 'Bastion Host'],
      { addReference: add.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(add.calls()).toEqual([
      {
        groupQuery: 'Engineering',
        credentialQuery: 'Primary DB',
        fieldQuery: 'depends_on',
        targetQuery: 'Bastion Host',
        allowCycle: false,
      },
    ]);
    expect(result.stdout).toContain(
      'Depends on (depends_on) of Primary DB now references Bastion Host (item.102) in Engineering.',
    );
    expect(result.stdout).toContain('Revision 4 -> 5.');
    expect(result.stdout).not.toContain('cycle');
  });

  it('forwards a cross-group target and a revision guard verbatim', async () => {
    const add = capturing<AddRequest, AddResult>(
      addResult({ targetGroupId: OTHER_GROUP_ID, targetGroupName: 'Infrastructure' }),
    );

    const result = await execute(
      [
        'reference',
        'add',
        'Engineering',
        'Primary DB',
        'depends_on',
        'Root CA',
        '--target-group',
        'Infrastructure',
        '--if-revision',
        '4',
      ],
      { addReference: add.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    // A cross-group target must not be silently resolved inside the source
    // group, so the group the operator named has to survive the round trip.
    expect(add.calls()).toEqual([
      {
        groupQuery: 'Engineering',
        credentialQuery: 'Primary DB',
        fieldQuery: 'depends_on',
        targetQuery: 'Root CA',
        targetGroupQuery: 'Infrastructure',
        allowCycle: false,
        ifRevision: 4,
      },
    ]);
    expect(result.stdout).toContain('in Infrastructure.');
  });

  it('reports an existing reference as unchanged instead of claiming a write', async () => {
    const add = capturing<AddRequest, AddResult>(
      addResult({ alreadyPresent: true, previousRevision: 4, revision: 4 }),
    );

    const result = await execute(
      ['reference', 'add', 'Engineering', 'Primary DB', 'depends_on', 'Bastion Host'],
      { addReference: add.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('already references Bastion Host (item.102).');
    // Announcing a revision bump that never happened would make a no-op look
    // like an edit in anything reading this output.
    expect(result.stdout).toContain('Revision 4 is unchanged.');
    expect(result.stdout).not.toContain('->');
  });

  it('names the cycle it closed when the operator allowed one', async () => {
    const add = capturing<AddRequest, AddResult>(
      addResult({ cyclePath: [TARGET_ID, DEEP_ID] }),
    );

    const result = await execute(
      [
        'reference',
        'add',
        'Engineering',
        'Primary DB',
        'depends_on',
        'Bastion Host',
        '--allow-cycle',
      ],
      { addReference: add.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(add.calls()[0]?.allowCycle).toBe(true);
    // The loop is legal once acknowledged, but it is still disclosed: an
    // unannounced cycle is what makes a reference set unnavigable later.
    expect(result.stdout).toContain('Allowed cycle: item.102 -> item.103 -> item.101.');
  });

  it('refuses a blank, hostile, or malformed write before opening the vault', async () => {
    const add = capturing<AddRequest, AddResult>(addResult());

    for (const argv of [
      ['reference', 'add', '  ', 'Primary DB', 'depends_on', 'Bastion Host'],
      ['reference', 'add', 'Engineering', '  ', 'depends_on', 'Bastion Host'],
      ['reference', 'add', 'Engineering', 'Primary DB', '  ', 'Bastion Host'],
      ['reference', 'add', 'Engineering', 'Primary DB', 'depends_on', '  '],
      [
        'reference',
        'add',
        'Engineering',
        'Primary DB',
        'depends_on',
        `Bastion${ESCAPE}[31m`,
      ],
      [
        'reference',
        'add',
        'Engineering',
        'Primary DB',
        'depends_on',
        'Bastion Host',
        '--target-group',
        '   ',
      ],
      [
        'reference',
        'add',
        'Engineering',
        'Primary DB',
        'depends_on',
        'Bastion Host',
        '--if-revision',
        '0',
      ],
      [
        'reference',
        'add',
        'Engineering',
        'Primary DB',
        'depends_on',
        'Bastion Host',
        '--if-revision',
        'later',
      ],
    ]) {
      const result = await execute(argv, { addReference: add.port });
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
    }
    expect(add.calls()).toHaveLength(0);
  });

  it('neutralizes hostile endpoint titles in both output modes', async () => {
    const hostile = addResult({
      title: `Primary${ESCAPE}]0;pwned${BELL}`,
      targetTitle: `Bastion${ESCAPE}[2K`,
      targetGroupName: `Engineering${ESCAPE}[31m`,
    });

    const text = await execute(
      ['reference', 'add', 'Engineering', 'Primary DB', 'depends_on', 'Bastion Host'],
      { addReference: capturing<AddRequest, AddResult>(hostile).port },
    );
    const json = await execute(
      [
        'reference',
        'add',
        'Engineering',
        'Primary DB',
        'depends_on',
        'Bastion Host',
        '--json',
      ],
      { addReference: capturing<AddRequest, AddResult>(hostile).port },
    );

    expect(text.stdout).not.toContain(ESCAPE);
    expect(text.stdout).not.toContain(BELL);
    expect(text.stdout).toContain(REPLACEMENT);

    expect(json.stdout).not.toContain(ESCAPE);
    expect(json.stdout).not.toContain(BELL);
    const parsed = JSON.parse(json.stdout) as AddResult;
    expect(parsed.targetTitle).toContain(REPLACEMENT);
    expect(parsed.revision).toBe(5);
  });

  it('reports an unconfigured adapter as unavailable rather than crashing', async () => {
    const result = await execute([
      'reference',
      'add',
      'Engineering',
      'Primary DB',
      'depends_on',
      'Bastion Host',
    ]);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('reference add is unavailable');
    expect(result.stdout).toBe('');
  });
});

describe('CLI reference remove command', () => {
  it('drops a reference and says the relation went with it', async () => {
    const remove = capturing<RemoveRequest, RemoveResult>(removeResult());

    const result = await execute(
      ['reference', 'remove', 'Engineering', 'Primary DB', 'depends_on'],
      { removeReference: remove.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(remove.calls()).toEqual([
      {
        groupQuery: 'Engineering',
        credentialQuery: 'Primary DB',
        fieldQuery: 'depends_on',
      },
    ]);
    expect(result.stdout).toContain(
      'Depends on (depends_on) of Primary DB no longer references Bastion Host (item.102).',
    );
    expect(result.stdout).toContain(
      'The relation was removed because no other field bound this target.',
    );
    expect(result.stdout).toContain('Revision 4 -> 5.');
  });

  it('says the relation survives when another field still binds the target', async () => {
    const remove = capturing<RemoveRequest, RemoveResult>(
      removeResult({ relationRemoved: false }),
    );

    const result = await execute(
      [
        'reference',
        'remove',
        'Engineering',
        'Primary DB',
        'upstream',
        '--target',
        'Bastion Host',
      ],
      { removeReference: remove.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(remove.calls()).toEqual([
      {
        groupQuery: 'Engineering',
        credentialQuery: 'Primary DB',
        fieldQuery: 'upstream',
        targetQuery: 'Bastion Host',
      },
    ]);
    // Retiring the relation while a second field still pointed at the target
    // would strand that field, so the distinction is stated outright.
    expect(result.stdout).toContain(
      'The relation is kept because another field still binds this target.',
    );
  });

  it('removes a reference whose target no longer resolves', async () => {
    const remove = capturing<RemoveRequest, RemoveResult>(
      unresolvedRemoveResult('item.999'),
    );

    const result = await execute(
      [
        'reference',
        'remove',
        'Engineering',
        'Primary DB',
        'depends_on',
        '--target',
        'item.999',
      ],
      { removeReference: remove.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    // A relation can outlive its target, and an unresolvable edge that could
    // never be cleaned up would stay in the vault forever.
    expect(result.stdout).toContain('no longer references (unresolved) (item.999).');
  });

  it('forwards a cross-group target and a revision guard verbatim', async () => {
    const remove = capturing<RemoveRequest, RemoveResult>(removeResult());

    const result = await execute(
      [
        'reference',
        'remove',
        'Engineering',
        'Primary DB',
        'depends_on',
        '--target',
        'Root CA',
        '--target-group',
        'Infrastructure',
        '--if-revision',
        '4',
      ],
      { removeReference: remove.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(remove.calls()).toEqual([
      {
        groupQuery: 'Engineering',
        credentialQuery: 'Primary DB',
        fieldQuery: 'depends_on',
        targetQuery: 'Root CA',
        targetGroupQuery: 'Infrastructure',
        ifRevision: 4,
      },
    ]);
  });

  it('refuses a blank, hostile, or malformed removal before opening the vault', async () => {
    const remove = capturing<RemoveRequest, RemoveResult>(removeResult());

    for (const argv of [
      ['reference', 'remove', '  ', 'Primary DB', 'depends_on'],
      ['reference', 'remove', 'Engineering', '  ', 'depends_on'],
      ['reference', 'remove', 'Engineering', 'Primary DB', '  '],
      ['reference', 'remove', 'Engineering', 'Primary DB', `depends${ESCAPE}[31m`],
      [
        'reference',
        'remove',
        'Engineering',
        'Primary DB',
        'depends_on',
        '--target',
        '   ',
      ],
      [
        'reference',
        'remove',
        'Engineering',
        'Primary DB',
        'depends_on',
        '--if-revision',
        '0',
      ],
    ]) {
      const result = await execute(argv, { removeReference: remove.port });
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
    }
    expect(remove.calls()).toHaveLength(0);
  });

  it('neutralizes hostile titles in both output modes', async () => {
    const hostile = removeResult({
      title: `Primary${ESCAPE}]0;pwned${BELL}`,
      targetTitle: `Bastion${ESCAPE}[2K`,
    });

    const text = await execute(
      ['reference', 'remove', 'Engineering', 'Primary DB', 'depends_on'],
      { removeReference: capturing<RemoveRequest, RemoveResult>(hostile).port },
    );
    const json = await execute(
      ['reference', 'remove', 'Engineering', 'Primary DB', 'depends_on', '--json'],
      { removeReference: capturing<RemoveRequest, RemoveResult>(hostile).port },
    );

    expect(text.stdout).not.toContain(ESCAPE);
    expect(text.stdout).not.toContain(BELL);
    expect(text.stdout).toContain(REPLACEMENT);

    expect(json.stdout).not.toContain(ESCAPE);
    expect(json.stdout).not.toContain(BELL);
    const parsed = JSON.parse(json.stdout) as RemoveResult;
    expect(parsed.targetTitle).toContain(REPLACEMENT);
    expect(parsed.relationRemoved).toBe(true);
  });

  it('reports an unconfigured adapter as unavailable rather than crashing', async () => {
    const result = await execute([
      'reference',
      'remove',
      'Engineering',
      'Primary DB',
      'depends_on',
    ]);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('reference remove is unavailable');
    expect(result.stdout).toBe('');
  });
});
