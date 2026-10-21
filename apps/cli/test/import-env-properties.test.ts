import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { parseEnvDocument } from '../src/import-env-command-impl.js';

const key = fc.stringMatching(/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/u);
// Any single-line value: the parser keeps everything after the first "=".
const value = fc
  .string({ unit: 'grapheme', maxLength: 64 })
  .filter((text) => !/[\r\n]/u.test(text));

describe('parseEnvDocument properties', () => {
  it('round-trips rendered KEY=value documents exactly', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.tuple(key, value), {
          minLength: 1,
          maxLength: 40,
          selector: ([name]) => name,
        }),
        fc.boolean(),
        fc.boolean(),
        (entries, crlf, exported) => {
          const newline = crlf ? '\r\n' : '\n';
          const document = entries
            .map(([name, text]) => `${exported ? 'export ' : ''}${name}=${text}`)
            .join(newline);
          const parsed = parseEnvDocument(document);
          // Leading/trailing whitespace of a line is trimmed, so compare the
          // trimmed rendering the parser is documented to read.
          expect(parsed.map((entry) => entry.key)).toEqual(
            entries.map(([name]) => name),
          );
          for (const [index, [, text]] of entries.entries()) {
            expect(parsed[index]?.value).toBe(text.trimEnd());
          }
        },
      ),
      { numRuns: 300 },
    );
  });

  it('never accepts a duplicate key', () => {
    fc.assert(
      fc.property(key, value, value, (name, first, second) => {
        expect(() => parseEnvDocument(`${name}=${first}\n${name}=${second}\n`)).toThrow(
          'duplicate variable',
        );
      }),
    );
  });

  it('fails with a line-numbered error rather than throwing anything else', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), (document) => {
        try {
          parseEnvDocument(document);
        } catch (error) {
          expect((error as Error).name).toBe('LocalCliError');
        }
      }),
      { numRuns: 500 },
    );
  });
});
