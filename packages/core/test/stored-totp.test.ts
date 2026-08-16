import {
  fieldDefinitionSchema,
  fieldValueSchema,
  secretValueSchema,
  type FieldDefinition,
  type FieldType,
  type FieldValue,
} from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  AmbiguousNameError,
  NotFoundError,
  PermissionError,
  ValidationError,
} from '../src/errors.js';
import {
  TOTP_SECRET_FIELD_TYPE,
  assertTotpRevealPermitted,
  assertTotpSecretField,
  generateStoredTotpCode,
  selectTotpSecretField,
} from '../src/policies/stored-totp.js';
import type * as TotpModule from '../src/totp.js';
import type { TotpConfiguration } from '../src/totp.js';

const observed = vi.hoisted(() => ({
  secrets: [] as { readonly destroyed: boolean }[],
}));

// The policy owns the decoded seed buffer and must wipe it on every exit path.
// Recording each instance the policy creates is the only way to observe that
// wipe from outside, because no exported API hands the seed back.
vi.mock('../src/totp.js', async (importOriginal) => {
  const actual = await importOriginal<typeof TotpModule>();
  return {
    ...actual,
    parseTotpSecret: (encoded: Parameters<typeof actual.parseTotpSecret>[0]) => {
      const secret = actual.parseTotpSecret(encoded);
      observed.secrets.push(secret);
      return secret;
    },
  };
});

const CREATED_AT = '2026-08-10T00:00:00.000Z';

/**
 * The RFC 6238 seeds and expectations, restated here rather than shared with the
 * local-seed suite.
 *
 * Issue #68 requires the published vectors to stay unchanged once a seed can be
 * read out of a vault, so the stored path is checked against the specification
 * itself. A shared helper would let both paths drift together and still agree.
 */
const RFC_SEEDS = Object.freeze({
  sha1: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  sha256: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  sha512:
    'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
});

const RFC_VECTORS = [
  [59, '94287082', '46119246', '90693936'],
  [1_111_111_109, '07081804', '68084774', '25091201'],
  [1_111_111_111, '14050471', '67062674', '99943326'],
  [1_234_567_890, '89005924', '91819424', '93441116'],
  [2_000_000_000, '69279037', '90698825', '38618901'],
  [20_000_000_000, '65353130', '77737706', '47863826'],
] as const;

interface DefinitionOverrides {
  readonly id?: string;
  readonly stableKey?: string;
  readonly label?: string;
  readonly type?: FieldType;
  readonly revealPolicy?: FieldDefinition['revealPolicy'];
}

function definition(overrides: DefinitionOverrides = {}): FieldDefinition {
  return fieldDefinitionSchema.parse({
    id: overrides.id ?? 'field.totp',
    stableKey: overrides.stableKey ?? 'totp-secret',
    label: overrides.label ?? 'Authenticator seed',
    type: overrides.type ?? TOTP_SECRET_FIELD_TYPE,
    required: false,
    sensitive: true,
    repeatable: false,
    copyable: true,
    searchableLocally: false,
    showInPreview: false,
    copyPolicy: 'allowed',
    revealPolicy: overrides.revealPolicy ?? 'timed',
    reauthenticationPolicy: 'after-lock',
    exportPolicy: 'guarded',
    sortOrder: 0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
}

/** Builds the one stored shape a seed may legally occupy. */
function seed(encoded: string): FieldValue {
  return fieldValueSchema.parse({
    version: 1,
    state: 'present',
    content: {
      cardinality: 'single',
      value: { kind: 'secret', value: secretValueSchema.parse(encoded) },
    },
  });
}

function configuration(
  algorithm: TotpConfiguration['algorithm'],
  digits: 6 | 7 | 8 = 8,
  periodSeconds = 30,
): TotpConfiguration {
  return { algorithm, digits, periodSeconds };
}

function candidate(
  field: FieldDefinition,
): Readonly<{ id: string; definition: FieldDefinition }> {
  return { id: field.id, definition: field };
}

describe('stored TOTP field guard', () => {
  it('accepts only the field type whose stored value is a TOTP seed', () => {
    expect(() => {
      assertTotpSecretField(definition());
    }).not.toThrow();

    for (const type of [
      'secret',
      'api-key',
      'recovery-code-list',
      'text',
      'private-key',
    ] as const) {
      expect(() => {
        assertTotpSecretField(definition({ type }));
      }).toThrow(ValidationError);
      expect(() => {
        assertTotpSecretField(definition({ type }));
      }).toThrow(/does not hold a TOTP secret/u);
    }
  });

  it('refuses a field its own definition says must never be revealed', () => {
    // A generated code is short-lived rather than permanent, but it still
    // authenticates, so a `never` reveal policy is honoured exactly as it is for
    // a recovery code.
    expect(() => {
      assertTotpRevealPermitted(definition({ revealPolicy: 'never' }));
    }).toThrow(PermissionError);

    for (const revealPolicy of ['timed', 'confirm'] as const) {
      expect(() => {
        assertTotpRevealPermitted(definition({ revealPolicy }));
      }).not.toThrow();
    }
  });
});

describe('stored TOTP field selection', () => {
  const totp = definition();
  const password = definition({
    id: 'field.password',
    stableKey: 'password',
    label: 'Password',
    type: 'secret',
  });
  const second = definition({
    id: 'field.totp.backup',
    stableKey: 'totp-backup',
    label: 'Backup authenticator seed',
  });

  it('selects the one seed field a credential holds', () => {
    expect(selectTotpSecretField([password, totp].map(candidate)).id).toBe(
      'field.totp',
    );
  });

  it('reports a credential with no seed as not found', () => {
    expect(() => selectTotpSecretField([password].map(candidate))).toThrow(
      NotFoundError,
    );
    expect(() => selectTotpSecretField([])).toThrow(NotFoundError);
  });

  it('refuses to guess between two seeds and names both identifiers', () => {
    // Guessing here would silently generate a code for the wrong account, which
    // is indistinguishable from a wrong code at the relying party.
    let thrown: unknown;
    try {
      selectTotpSecretField([totp, password, second].map(candidate));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AmbiguousNameError);
    expect((thrown as AmbiguousNameError).candidateIds).toEqual([
      'field.totp',
      'field.totp.backup',
    ]);
  });
});

describe('stored TOTP generation', () => {
  it.each(RFC_VECTORS)(
    'reproduces the published vectors from a stored seed at Unix time %i',
    (unixTimeSeconds, sha1, sha256, sha512) => {
      const expected = { sha1, sha256, sha512 } as const;
      for (const algorithm of ['sha1', 'sha256', 'sha512'] as const) {
        expect(
          generateStoredTotpCode(
            definition(),
            seed(RFC_SEEDS[algorithm]),
            configuration(algorithm),
            unixTimeSeconds,
          ).code,
        ).toBe(expected[algorithm]);
      }
    },
  );

  it('reports the remaining lifetime of the code it just produced', () => {
    expect(
      generateStoredTotpCode(
        definition(),
        seed(RFC_SEEDS.sha1),
        configuration('sha1'),
        59,
      ),
    ).toEqual({
      code: '94287082',
      remainingSeconds: 1,
      configuration: configuration('sha1'),
    });
    expect(
      generateStoredTotpCode(
        definition(),
        seed(RFC_SEEDS.sha1),
        configuration('sha1'),
        60,
      ).remainingSeconds,
    ).toBe(30);
  });

  it('returns nothing from which the stored seed could be recovered', () => {
    const generation = generateStoredTotpCode(
      definition(),
      seed(RFC_SEEDS.sha1),
      configuration('sha1', 6),
      59,
    );

    const serialized = JSON.stringify(generation);
    for (const encoded of Object.values(RFC_SEEDS)) {
      expect(serialized).not.toContain(encoded);
    }
    expect(Object.keys(generation).sort()).toEqual([
      'code',
      'configuration',
      'remainingSeconds',
    ]);
  });

  it('wipes the decoded seed after a successful generation', () => {
    observed.secrets.length = 0;

    generateStoredTotpCode(
      definition(),
      seed(RFC_SEEDS.sha1),
      configuration('sha1'),
      59,
    );

    expect(observed.secrets).toHaveLength(1);
    expect(observed.secrets[0]?.destroyed).toBe(true);
  });

  it('wipes the decoded seed when generation throws', () => {
    // The seed is already decoded by the time an out-of-range policy is
    // rejected, so an exception must clean up on exactly the same path a
    // success does.
    observed.secrets.length = 0;

    expect(() =>
      generateStoredTotpCode(
        definition(),
        seed(RFC_SEEDS.sha1),
        { algorithm: 'sha1', digits: 6, periodSeconds: 4 },
        59,
      ),
    ).toThrow(ValidationError);

    expect(observed.secrets).toHaveLength(1);
    expect(observed.secrets[0]?.destroyed).toBe(true);
  });

  it('rejects a tampered or non-canonical stored seed generically', () => {
    for (const encoded of [
      RFC_SEEDS.sha1.toLowerCase(),
      `${RFC_SEEDS.sha1}=`,
      ` ${RFC_SEEDS.sha1}`,
      'AAAAAAAAAAAAAAAAAAAAAAAA',
      'GEZDGNBVGY3TQOJQGEZDGNBVGZ',
      'GEZDGNBVGY3TQOJQGEZDGNBVGYA',
      'otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    ]) {
      let thrown: unknown;
      try {
        generateStoredTotpCode(definition(), seed(encoded), configuration('sha1'), 59);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(ValidationError);
      // The refusal names the seed format, never the offending bytes.
      expect((thrown as ValidationError).message).not.toContain(encoded);
    }
  });

  it('refuses a field whose type says it holds something other than a seed', () => {
    expect(() =>
      generateStoredTotpCode(
        definition({ type: 'secret' }),
        seed(RFC_SEEDS.sha1),
        configuration('sha1'),
        59,
      ),
    ).toThrow(/does not hold a TOTP secret/u);
  });

  it('refuses every stored state that is not exactly one readable seed', () => {
    const field = definition();
    const cases: readonly (readonly [FieldValue | undefined, RegExp])[] = [
      [undefined, /no TOTP secret yet/u],
      [fieldValueSchema.parse({ version: 1, state: 'missing' }), /no TOTP secret yet/u],
      [fieldValueSchema.parse({ version: 1, state: 'empty' }), /is empty/u],
      [
        fieldValueSchema.parse({ version: 1, state: 'inapplicable' }),
        /marked inapplicable/u,
      ],
      [
        fieldValueSchema.parse({
          version: 1,
          state: 'unreadable',
          reason: 'decryption-failed',
        }),
        /cannot be read/u,
      ],
      [
        fieldValueSchema.parse({
          version: 1,
          state: 'orphaned',
          originalValue: { version: 1, state: 'empty' },
        }),
        /archived/u,
      ],
      [
        fieldValueSchema.parse({
          version: 1,
          state: 'present',
          content: {
            cardinality: 'multiple',
            elements: [
              {
                id: 'seed.a',
                value: {
                  kind: 'secret',
                  value: secretValueSchema.parse(RFC_SEEDS.sha1),
                },
                lifecycle: { version: 1, status: 'available' },
              },
            ],
          },
        }),
        /list rather than one seed/u,
      ],
      [
        fieldValueSchema.parse({
          version: 1,
          state: 'present',
          content: {
            cardinality: 'single',
            value: { kind: 'text', value: RFC_SEEDS.sha1 },
          },
        }),
        /no readable seed/u,
      ],
    ];

    for (const [value, message] of cases) {
      expect(() =>
        generateStoredTotpCode(field, value, configuration('sha1'), 59),
      ).toThrow(ValidationError);
      expect(() =>
        generateStoredTotpCode(field, value, configuration('sha1'), 59),
      ).toThrow(message);
    }
  });

  it('never treats an unreadable seed as an absent one', () => {
    // Reporting "no seed" here would invite a caller to overwrite a seed that is
    // still stored but temporarily unreadable.
    expect(() =>
      generateStoredTotpCode(
        definition(),
        fieldValueSchema.parse({
          version: 1,
          state: 'unreadable',
          reason: 'invalid-encoding',
        }),
        configuration('sha1'),
        59,
      ),
    ).toThrow(/cannot be read/u);
  });

  it('decodes no seed at all when the field type is wrong', () => {
    observed.secrets.length = 0;

    expect(() =>
      generateStoredTotpCode(
        definition({ type: 'secret' }),
        seed(RFC_SEEDS.sha1),
        configuration('sha1'),
        59,
      ),
    ).toThrow(ValidationError);

    expect(observed.secrets).toHaveLength(0);
  });
});
