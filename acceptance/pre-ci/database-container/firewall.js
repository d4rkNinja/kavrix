/* global process */
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

/** Run every new workflow against the installed archive, not source imports. */
export async function exerciseFirewallExtensions(context) {
  const {
    run,
    paths,
    bin,
    addFileProfile,
    initializeDatabase,
    createVault,
    profileRoute,
    parseJson,
    assert,
    ephemeralSecret,
    assertNoSensitiveText,
  } = context;
  const root = dirname(paths.primaryDataFile);
  const passphrase = ephemeralSecret('structured-owner');
  const value = ephemeralSecret('structured-field');
  const nextValue = ephemeralSecret('structured-field-updated');
  const archivePassphrase = ephemeralSecret('structured-archive');
  const artifacts = [];
  async function setup(profile) {
    const dataFile = join(root, `${profile}.database`);
    const keyFile = join(root, `${profile}.key`);
    await addFileProfile(run, paths, profile, dataFile, keyFile);
    await initializeDatabase(run, paths, profile, passphrase, 'structured acceptance');
    const vaultId = await createVault(run, paths, profile, passphrase, 'structured');
    artifacts.push(dataFile, keyFile, `${keyFile}.database-anchor`);
    return {
      dataFile,
      keyFile,
      route: [
        ...profileRoute(paths, profile),
        '--vault',
        vaultId,
        '--passphrase-stdin',
        '--json',
      ],
    };
  }
  const source = await setup('structured-source');
  const target = await setup('structured-target');
  const route = source.route;
  const hierarchy = ['--context', 'packed-project', '--service', 'api'];
  const fieldRoute = [...hierarchy, '--item', 'deploy'];
  const reference = 'field:packed-project/api/deploy/token';
  const args = [
    '-e',
    `process.exit(require('node:crypto').createHash('sha256').update(process.env.PACKED_TOKEN ?? '').digest('hex') === '${createHash('sha256').update(value).digest('hex')}' ? 0 : 3)`,
  ];
  const call = (args, frames = [passphrase]) => run(args, frames);
  await call(['context', 'create', 'packed-project', ...route]);
  await call(['service', 'create', 'api', '--context', 'packed-project', ...route]);
  await call(['item', 'create', 'deploy', ...hierarchy, ...route]);
  await call(
    [
      'field',
      'set',
      'token',
      ...fieldRoute,
      '--type',
      'api-key',
      '--value-stdin',
      ...route,
    ],
    [passphrase, value],
  );
  await call(
    [
      'note',
      'add',
      'deploy',
      'runbook',
      ...hierarchy,
      '--content-stdin',
      '--sensitive',
      ...route,
    ],
    [passphrase, ephemeralSecret('structured-note')],
  );
  await call(['policy', 'mode', 'required', ...route]);
  const unguarded = await run(
    [
      'run',
      '--no-config',
      '--secret',
      `PACKED_TOKEN=${reference}`,
      ...route,
      '--',
      process.execPath,
      ...args,
    ],
    [passphrase],
    { allowFailure: true },
  );
  assert(
    unguarded.code === 12,
    'required policy mode permitted an unguarded packed invocation',
  );
  await call([
    'policy',
    'create',
    'packed-structured',
    '--secret',
    reference,
    '--command',
    'node',
    '--operation',
    JSON.stringify({ command: 'node', args }),
    ...route,
  ]);
  await call([
    'run',
    '--policy',
    'packed-structured',
    '--secret',
    `PACKED_TOKEN=${reference}`,
    ...route,
    '--',
    process.execPath,
    ...args,
  ]);
  const wrongOperation = await run(
    [
      'policy',
      'check',
      'packed-structured',
      ...route,
      '--',
      process.execPath,
      ...args,
      'extra',
    ],
    [passphrase],
    { allowFailure: true },
  );
  assert(
    wrongOperation.code === 12,
    'packed policy check accepted extra operation arguments',
  );
  await call(
    [
      'field',
      'set',
      'token',
      ...fieldRoute,
      '--type',
      'api-key',
      '--value-stdin',
      ...route,
    ],
    [passphrase, nextValue],
  );
  const history = parseJson(
    await call(['item', 'history', 'list', 'deploy', ...hierarchy, ...route]),
    'packed restorable history',
  );
  const snapshot = history.history.filter((entry) => entry.restorable === true).at(-1);
  assert(snapshot !== undefined, 'packed edit did not retain a restorable snapshot');
  await call([
    'item',
    'history',
    'restore',
    'deploy',
    snapshot.version,
    ...hierarchy,
    ...route,
  ]);
  await call([
    'run',
    '--policy',
    'packed-structured',
    '--secret',
    `PACKED_TOKEN=${reference}`,
    ...route,
    '--',
    process.execPath,
    ...args,
  ]);
  const archiveFile = join(root, 'structured-transfer.archive');
  artifacts.push(archiveFile);
  await call(
    ['export', '--structured', '--include-policies', '--file', archiveFile, ...route],
    [passphrase, archivePassphrase, archivePassphrase],
  );
  await call(
    ['import', 'archive', '--file', archiveFile, ...target.route],
    [passphrase, archivePassphrase],
  );
  const candidates = parseJson(
    await call(['policy', 'candidates', ...target.route]),
    'packed policy candidates',
  );
  assert(
    Object.hasOwn(candidates.candidates, 'packed-structured'),
    'structured transfer lost its policy candidate',
  );
  const beforeApproval = await run(
    [
      'run',
      '--secret',
      `PACKED_TOKEN=${reference}`,
      ...target.route,
      '--',
      process.execPath,
      ...args,
    ],
    [passphrase],
    { allowFailure: true },
  );
  assert(
    beforeApproval.code === 12,
    'structured import activated authority without approval',
  );
  await call(['policy', 'import', 'packed-structured', ...target.route]);
  await call([
    'run',
    '--policy',
    'packed-structured',
    '--secret',
    `PACKED_TOKEN=${reference}`,
    ...target.route,
    '--',
    process.execPath,
    ...args,
  ]);
  const notes = parseJson(
    await call(['note', 'list', 'deploy', ...hierarchy, ...target.route]),
    'packed imported notes',
  );
  assert(notes.notes.length === 1, 'structured transfer lost item notes');

  // The agent sees references and a broker capability, never vault values.
  await call(
    ['add', 'blocked/value', '--value-stdin', ...route],
    [passphrase, ephemeralSecret('blocked-agent-field')],
  );
  await call([
    'policy',
    'create',
    'packed-blocked',
    '--secret',
    'blocked/value',
    '--deny',
    ...route,
  ]);
  const config = join(root, 'structured-agent.json');
  await writeFile(
    config,
    JSON.stringify({
      version: 1,
      agents: {
        reviewer: {
          permissions: {
            once: {
              secret: reference,
              commands: ['node'],
              env: 'PACKED_TOKEN',
              maxUses: 1,
              operations: [{ command: 'node', args }],
            },
            blocked: {
              secret: 'field:Default%20project/Default%20service/blocked%2Fvalue/value',
              commands: ['node'],
              env: 'PACKED_TOKEN',
            },
          },
        },
      },
    }),
  );
  const agentCode = `const {spawnSync}=require('node:child_process');const bin=process.argv[1];const args=${JSON.stringify(args)};const exits=['once','once','blocked'].map(permission=>spawnSync(process.execPath,[bin,'agent','exec',permission,'--',process.execPath,...args],{encoding:'utf8',windowsHide:true,shell:false}).status);process.exit(JSON.stringify(exits)==='[0,1,1]'?0:3);`;
  const agent = parseJson(
    await call([
      'agent',
      'run',
      '--agent',
      'reviewer',
      '--config',
      config,
      ...route,
      '--',
      process.execPath,
      '-e',
      agentCode,
      bin,
    ]),
    'packed agent enforcement',
  );
  assert(
    agent.allowedRequests === 1 && agent.deniedRequests === 2,
    'packed broker failed use-limit or stored-deny enforcement',
  );

  await call([
    'grant',
    'create',
    reference,
    '--command',
    'node',
    '--env',
    'PACKED_TOKEN',
    '--ttl',
    '15m',
    '--max-uses',
    '1',
    ...route,
  ]);
  const backupFile = join(root, 'structured-firewall.backup');
  artifacts.push(
    backupFile,
    `${source.keyFile}.authorization`,
    `${target.keyFile}.authorization`,
  );
  await call(
    [
      'backup',
      'create',
      '--include-firewall',
      '--file',
      backupFile,
      ...profileRoute(paths, 'structured-source'),
      '--passphrase-stdin',
      '--json',
    ],
    [archivePassphrase, archivePassphrase],
  );
  await call(
    ['backup', 'verify', '--file', backupFile, '--passphrase-stdin', '--json'],
    [archivePassphrase],
  );
  const restoredFile = join(root, 'structured-restored.database');
  artifacts.push(restoredFile);
  const restored = parseJson(
    await call(
      [
        'backup',
        'restore',
        '--file',
        backupFile,
        '--data-file',
        restoredFile,
        '--passphrase-stdin',
        '--json',
      ],
      [archivePassphrase],
    ),
    'packed complete backup restore',
  );
  assert(
    restored.firewallPending === true,
    'full database restore did not report pending firewall recovery',
  );
  assert(
    (await readFile(restoredFile)).equals(await readFile(source.dataFile)),
    'full backup changed database bytes',
  );
  const firewall = parseJson(
    await call(
      ['backup', 'restore-firewall', '--file', backupFile, '--overwrite', ...route],
      [passphrase, archivePassphrase],
    ),
    'packed firewall recovery',
  );
  assert(
    firewall.firewallRestored === true && firewall.discardedGrants === 1,
    'firewall recovery resurrected or lost track of archived authority',
  );
  const state = parseJson(
    await call(['policy', 'snapshot', ...route]),
    'packed restored firewall state',
  );
  assert(
    Object.keys(state.grants).length === 0 &&
      state.policies['packed-blocked'].definition.deny === true,
    'firewall recovery did not retain deny rules and discard grants',
  );
  for (const file of artifacts)
    assertNoSensitiveText(
      (await readFile(file)).toString('utf8'),
      'structured workflow artifact',
    );
}
