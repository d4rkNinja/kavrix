# Default Vault Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each protected datastore profile select one authenticated default database vault so current commands can omit repeated opaque `--vault` arguments without changing legacy version-2 routing.

**Architecture:** Evolve the protected profile registry from version 1 to version 2 with an optional `defaultVaultId`, accepting version 1 only through a strict lazy migration. Add authenticated `kavrix db vault use <vaultId>` composition, then centralize database-vault resolution so explicit input wins, omission uses the profile default, and legacy standalone commands retain the literal `default` vault.

**Tech Stack:** Strict ESM TypeScript, Commander 15, Zod 4, protected canonical JSON from `@kavrix/key-files`, Vitest 4, pnpm 11.

**Spec:** `docs/superpowers/specs/2026-08-31-local-first-multidevice-team-database-design.md`

## Global Constraints

- Persist no secrets, MongoDB URIs, passphrases, keys, decrypted labels, or credential values.
- A default is routing metadata, not authorization; authenticate the selected vault through its bound database.
- Explicit `--vault` always wins. A missing database default fails before secret input.
- Legacy standalone commands retain `default` when `--vault` is omitted.
- Unknown versions/keys, unsafe files, cross-profile writes, and binding mismatches fail closed.
- Use exact optional-property construction. Add no dependencies or lockfile changes.
- Do not commit automatically. Commit snippets are review checkpoints only.
- Preserve the pre-existing untracked `.pnpm-store/` directory.

## File structure

- `apps/cli/src/datastore-profiles.ts`: registry v1/v2 parsing and default selection mutation.
- `apps/cli/src/database-commands.ts`: authenticated `db vault use` composition.
- `apps/cli/src/database-flat-commands.ts`: canonical selected database-vault resolver.
- `apps/cli/src/local-vault-cli.ts`: Commander option-source evidence and legacy routing.
- `apps/cli/src/structured-vault-commands.ts`: optional structured-command vault selection.
- `apps/cli/src/execution/cli-options.ts`: omission evidence for run/policy/grant/audit/agent.
- Existing CLI tests: migration, selection, cross-family behavior, and packed evidence.

---

### Task 1: Profile-registry v2 and default-vault mutation

**Files:**

- Modify: `apps/cli/src/datastore-profiles.ts`
- Test: `apps/cli/test/datastore-profiles.test.ts`

**Interfaces:**

- Consumes: existing profile/database identifiers and protected JSON transitions.
- Produces:

```ts
type MongoDatastoreProfile = Readonly<{
  id: ProfileId;
  datastore: 'mongodb';
  databaseId?: DatabaseId;
  defaultVaultId?: VaultId;
  database: string;
  databaseCollection: string;
  vaultCollection: string;
  keyFile: string;
}>;

type FileDatastoreProfile = Readonly<{
  id: ProfileId;
  datastore: 'file';
  databaseId?: DatabaseId;
  defaultVaultId?: VaultId;
  dataFile: string;
  keyFile: string;
}>;

type DatastoreProfile = MongoDatastoreProfile | FileDatastoreProfile;

class DatastoreProfileRegistry {
  setDefaultVaultId(
    id: ProfileId,
    vaultId: VaultId,
    expectedDatabaseId: DatabaseId,
  ): Promise<DatastoreProfile>;
}
```

- [ ] **Step 1: Write failing migration and mutation tests**

Cover strict version-1 read without rewrite, mutation to canonical version 2, version-2 round trip, two-profile isolation, unbound/missing profile, `default`, malformed ID, unknown version/key, and sensitive-looking key rejection.

```ts
it('lazily promotes v1 and writes one bound profile default as v2', async () => {
  const registry = await openRegistryWithVersion1BoundProfile();
  expect((await registry.get(PROFILE_ID)).defaultVaultId).toBeUndefined();
  expect(
    (await registry.setDefaultVaultId(PROFILE_ID, VAULT_ID, DATABASE_ID))
      .defaultVaultId,
  ).toBe(VAULT_ID);
  await expect(readCanonicalRegistry()).resolves.toMatchObject({ version: 2 });
});
```

- [ ] **Step 2: Prove the tests fail before implementation**

```powershell
pnpm exec vitest run apps/cli/test/datastore-profiles.test.ts
```

Expected: failures because version 2 and `setDefaultVaultId` do not exist.

- [ ] **Step 3: Implement strict v1/v2 parsing and canonical v2 writes**

Branch on the literal document version before exact-key validation. V1 accepts only old profile keys and promotes in memory without a default. V2 accepts optional `defaultVaultId`. `emptyDocument()` and every mutation write v2. Validate the value through `vaultIdSchema` and require the `vault_` database namespace.

```ts
async setDefaultVaultId(
  id: ProfileId,
  vaultId: VaultId,
  expectedDatabaseId: DatabaseId,
): Promise<DatastoreProfile> {
  const parsedId = parseProfileId(id);
  const parsedVaultId = parseDatabaseDefaultVaultId(vaultId);
  return this.#mutate((document) => {
    const profile = document.profiles.find((entry) => entry.id === parsedId);
    if (profile?.databaseId !== expectedDatabaseId) {
      throw new DatastoreProfileError('PROFILE_INVALID');
    }
    const selected = parseProfile({ ...profile, defaultVaultId: parsedVaultId });
    return {
      document: {
        ...document,
        profiles: document.profiles.map((entry) =>
          entry.id === parsedId ? selected : entry,
        ),
      },
      result: cloneProfile(selected),
    };
  });
}
```

- [ ] **Step 4: Verify and review Task 1**

```powershell
pnpm exec vitest run apps/cli/test/datastore-profiles.test.ts
pnpm exec prettier --check apps/cli/src/datastore-profiles.ts apps/cli/test/datastore-profiles.test.ts
pnpm exec tsc -p apps/cli/tsconfig.json --pretty false
git diff --check -- apps/cli/src/datastore-profiles.ts apps/cli/test/datastore-profiles.test.ts
```

Expected: all checks exit 0. Suggested commit after separate authorization: `feat(cli): store a default vault per profile`.

### Task 2: Authenticated `db vault use`

**Files:**

- Modify: `apps/cli/src/database-commands.ts`
- Test: `apps/cli/test/database-commands.test.ts`

**Interfaces:**

- Consumes: `DatastoreProfileRegistry.setDefaultVaultId`, `DatabaseSession.getVault`, route and owner-session composition.
- Produces: `kavrix db vault use <vaultId>` and `{ selected: true, profile, vaultId }` sanitized JSON.

- [ ] **Step 1: Write failing authenticated-selection tests**

Cover current/explicit profile, existing vault, missing/malformed/foreign vault, unbound profile, failed registry publication, and authentication-before-registry-mutation.

```ts
it('authenticates a vault before selecting it', async () => {
  const created = await initializeDatabaseAndVault();
  await execute([PASSPHRASE], 'db', 'vault', 'use', created.vaultId, ...route);
  expect((await registry.current())?.defaultVaultId).toBe(created.vaultId);
});
```

- [ ] **Step 2: Prove the command test fails**

```powershell
pnpm exec vitest run apps/cli/test/database-commands.test.ts
```

Expected: failure because `db vault use` is absent.

- [ ] **Step 3: Register and compose selection**

Register `use <vaultId>` beside vault create/list/status/rename with identical routing and secret options. Expose an immutable resolved-route view to the owner-session callback, parse the vault ID, authenticate `session.getVault(vaultId)`, then publish the profile default through that exact registry/profile.

```ts
await withOwnerSession(options, [], async (session, _extras, route) => {
  const vaultId = parseVaultIdentifier(vaultIdInput);
  await session.getVault(vaultId);
  if (route.registry === null || route.profile === null) {
    throw new DatabaseSessionError('binding');
  }
  const selected = await route.registry.setDefaultVaultId(
    route.profile.id,
    vaultId,
    session.databaseId,
  );
  writeOutput({ selected: true, profile: selected.id, vaultId });
});
```

- [ ] **Step 4: Verify and review Task 2**

```powershell
pnpm exec vitest run apps/cli/test/database-commands.test.ts apps/cli/test/datastore-profiles.test.ts
pnpm exec prettier --check apps/cli/src/database-commands.ts apps/cli/test/database-commands.test.ts
pnpm exec tsc -p apps/cli/tsconfig.json --pretty false
git diff --check -- apps/cli/src/database-commands.ts apps/cli/test/database-commands.test.ts
```

Expected: all checks exit 0. Suggested commit after separate authorization: `feat(cli): authenticate default vault selection`.

### Task 3: Omitted-vault resolution across command families

**Files:**

- Modify: `apps/cli/src/database-flat-commands.ts`
- Modify: `apps/cli/src/local-vault-cli.ts`
- Modify: `apps/cli/src/structured-vault-commands.ts`
- Modify: `apps/cli/src/execution/cli-options.ts`
- Test: `apps/cli/test/database-flat-commands.test.ts`
- Test: `apps/cli/test/structured-vault-commands.test.ts`
- Test: `apps/cli/test/execution-run.test.ts`
- Test: `apps/cli/test/execution-agent.test.ts`
- Test: `apps/cli/test/execution-policy.test.ts`
- Test: `apps/cli/test/execution-policy-grants.test.ts`
- Test: `apps/cli/test/execution-internals.test.ts`

**Interfaces:**

- Consumes: `DatastoreProfile.defaultVaultId`.
- Produces:

```ts
type DatabaseFlatCommandOptions = Readonly<{
  profile?: string;
  profileConfigDir?: string;
  vault: string;
  vaultWasDefaulted?: true;
  datastore?: string;
  dataFile?: string;
  database?: string;
  collection?: string;
  keyFile?: string;
  routingOverrides?: DatastoreProfileRoutingOverrides;
  databaseUrlStdin?: boolean;
  passphraseStdin?: boolean;
  valueStdin?: boolean;
  valueStdinBase64?: boolean;
  allowInsecureTransport?: boolean;
}>;

export function resolveDatabaseVaultId(
  profile: DatastoreProfile,
  options: DatabaseFlatCommandOptions,
): VaultId;
```

- [ ] **Step 1: Write failing resolver and cross-family tests**

Cover omitted vault/default, explicit override, missing default before secret read, profile switching, flat/structured CRUD, `run`, `agent run`, and database-wide policy/grant/audit paths with `requireVaultSelection: false`.

```ts
it('rejects a missing default before requesting secrets', async () => {
  const read = vi.spyOn(LocalSecretInput.prototype, 'read');
  await expect(
    readDatabaseFlatSecrets(
      {
        profile: PROFILE_ID,
        vault: 'default',
        vaultWasDefaulted: true,
      },
      [],
    ),
  ).rejects.toThrow('Select one database vault');
  expect(read).not.toHaveBeenCalled();
});
```

- [ ] **Step 2: Prove the tests fail**

```powershell
pnpm exec vitest run apps/cli/test/database-flat-commands.test.ts apps/cli/test/structured-vault-commands.test.ts
```

Expected: failures because omission evidence and shared resolution do not exist.

- [ ] **Step 3: Preserve Commander option-source evidence**

Keep Commander’s legacy displayed default and add `vaultWasDefaulted: true` only when no hierarchy level explicitly supplied `--vault`. Change structured `.requiredOption('--vault <id>')` to `.option('--vault <id>', ..., 'default')`. Preserve the same evidence through execution option extraction.

```ts
if (!sourceIsExplicit('vault')) {
  merged['vaultWasDefaulted'] = true;
}
```

- [ ] **Step 4: Implement one fail-closed resolver and use it before prompts/open**

```ts
export function resolveDatabaseVaultId(
  profile: DatastoreProfile,
  options: DatabaseFlatCommandOptions,
): VaultId {
  const candidate =
    options.vaultWasDefaulted === true ? profile.defaultVaultId : options.vault;
  if (candidate === undefined) {
    throw new DatabaseFlatCommandError(
      "Select one database vault with --vault or 'kavrix db vault use'.",
    );
  }
  const parsed = vaultIdSchema.parse(candidate);
  if (!parsed.startsWith('vault_')) {
    throw new DatabaseFlatCommandError('Vault ID is invalid.');
  }
  return parsed;
}
```

Call it in `readDatabaseFlatSecrets` before `LocalSecretInput.read` when selection is required and again in `openDatabaseFlatVault`. Never fall back to `default` for a database profile. Preserve database-wide authorization access.

- [ ] **Step 5: Verify and review Task 3**

```powershell
pnpm exec vitest run apps/cli/test/database-flat-commands.test.ts apps/cli/test/structured-vault-commands.test.ts apps/cli/test/local-vault-cli-coverage.test.ts apps/cli/test/execution-run.test.ts apps/cli/test/execution-agent.test.ts apps/cli/test/execution-policy.test.ts apps/cli/test/execution-policy-grants.test.ts apps/cli/test/execution-internals.test.ts
pnpm exec prettier --check apps/cli/src/database-flat-commands.ts apps/cli/src/local-vault-cli.ts apps/cli/src/structured-vault-commands.ts apps/cli/src/execution/cli-options.ts apps/cli/test/database-flat-commands.test.ts apps/cli/test/structured-vault-commands.test.ts
pnpm exec tsc -p apps/cli/tsconfig.json --pretty false
git diff --check -- apps/cli/src apps/cli/test
```

Expected: defaults and overrides work, database-wide authorization remains unchanged, and standalone legacy commands retain `default`. Suggested commit after separate authorization: `feat(cli): use profile default vaults`.

### Task 4: Packed evidence and factual documentation

**Files:**

- Modify: `README.md`
- Modify: `apps/cli/README.md`
- Modify: `docs/cli-reference.md`
- Modify: `docs/implementation-status.md`
- Modify: `apps/cli/scripts/smoke-packed-package.js`
- Test: `apps/cli/test/package.test.ts`

**Interfaces:**

- Consumes: Tasks 1–3.
- Produces: packed help/flow evidence and factual shipped-command documentation only.

- [ ] **Step 1: Add failing packed assertions**

Assert that packed help lists `db vault use`, explicit legacy `--vault default` remains supported, and a fresh protected profile with an authenticated default can run one masked flat operation without `--vault`.

- [ ] **Step 2: Prove packed assertions fail**

```powershell
pnpm --filter kavrix run build
pnpm exec vitest run apps/cli/test/package.test.ts
```

- [ ] **Step 3: Update only observable documentation**

Document:

```text
kavrix db vault create --profile work
kavrix db vault use <vault-id> --profile work
kavrix put github/token --profile work
```

State that explicit `--vault` overrides the profile default and missing defaults fail before secret input. Do not claim guided setup, backup, sync, or collaboration is shipped.

- [ ] **Step 4: Run active release gates and review the full diff**

```powershell
pnpm exec vitest run apps/cli/test/package.test.ts
pnpm --filter kavrix run package:smoke
pnpm build
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
git diff --check
git status --short
git diff --stat
```

Expected: all local checks exit 0. Do not infer MongoDB or macOS/Linux evidence from unit tests. Verify that only this slice, its tests/docs, and the approved design/plan changed. Suggested commit after separate authorization: `docs: document default vault routing`.
