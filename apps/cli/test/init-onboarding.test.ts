import { describe, expect, it } from 'vitest';

import {
  InitOnboardingCancelledError,
  runInitOnboarding,
  writeInitOnboardingComplete,
} from '../src/init-onboarding.js';

type RunResult = Readonly<{
  result: Awaited<ReturnType<typeof runInitOnboarding>>;
  output: string;
  prompts: readonly string[];
}>;

async function run(answers: readonly string[], color = false): Promise<RunResult> {
  let index = 0;
  const output: string[] = [];
  const prompts: string[] = [];
  const result = await runInitOnboarding({
    color,
    question: async (prompt) => {
      prompts.push(prompt);
      const answer = answers[index];
      index += 1;
      if (answer === undefined) throw new Error('Test answer queue was exhausted.');
      return answer;
    },
    write: (text) => {
      output.push(text);
    },
  });
  return { result, output: output.join(''), prompts };
}

describe('init onboarding', () => {
  it('selects local storage by default and returns safe defaults', async () => {
    const { result, output, prompts } = await run(['', '', '', '', '']);

    expect(result).toEqual({
      datastore: 'file',
      dataFile: './kavrix.vault',
      keyFile: './kavrix.key',
    });
    expect(output).toContain('client-side encryption');
    expect(output).toContain('ciphertext-only');
    expect(output).toContain('recovery');
    expect(output).toContain('masked secret prompts');
    expect(output).not.toContain('\u001b');
    expect(prompts.join('')).not.toContain('./kavrix.vault');
  });

  it('returns MongoDB routing values without collecting or printing a URI', async () => {
    const enteredDatabase = 'private-database-name';
    const enteredCollection = 'private-collection-name';
    const enteredKeyPath = 'C:\\private\\portable.key';
    const { result, output, prompts } = await run([
      '',
      '2',
      `  ${enteredDatabase} `,
      ` ${enteredCollection} `,
      enteredKeyPath,
      '',
    ]);

    expect(result).toEqual({
      datastore: 'mongodb',
      database: enteredDatabase,
      collection: enteredCollection,
      keyFile: enteredKeyPath,
    });
    const transcript = `${output}${prompts.join('')}`;
    expect(transcript).not.toContain(enteredDatabase);
    expect(transcript).not.toContain(enteredCollection);
    expect(transcript).not.toContain(enteredKeyPath);
  });

  it('omits a whitespace-only optional database and retries control-only paths', async () => {
    const { result, output } = await run(['', '2', '   ', '', '\u001b', '', '']);

    expect(result).toEqual({
      datastore: 'mongodb',
      collection: 'kavrix_vaults',
      keyFile: './kavrix.key',
    });
    expect(output).toContain('Enter a non-empty value');
    expect(output).not.toContain('\u001b');
  });

  it('retries an invalid storage choice and supports back navigation', async () => {
    const invalidChoice = await run(['', 'not-a-choice', '', '', '', '', '']);
    expect(invalidChoice.result).toEqual({
      datastore: 'file',
      dataFile: './kavrix.vault',
      keyFile: './kavrix.key',
    });
    expect(invalidChoice.output).toContain(
      'Choose 1 for local encrypted file or 2 for MongoDB.',
    );

    const backToWelcome = await run(['', 'b', '', '', '', '', '']);
    expect(backToWelcome.result.datastore).toBe('file');
    expect(backToWelcome.output).toContain('STEP 1 / WELCOME & SECURITY');

    const backToStorage = await run(['', '2', 'b', '1', '', '', '']);
    expect(backToStorage.result).toEqual({
      datastore: 'file',
      dataFile: './kavrix.vault',
      keyFile: './kavrix.key',
    });
  });

  it('throws a dedicated cancellation error without including input', async () => {
    let index = 0;
    const output: string[] = [];
    await expect(
      runInitOnboarding({
        question: async () => {
          index += 1;
          return index === 1 ? '' : 'q';
        },
        write: (text) => output.push(text),
      }),
    ).rejects.toBeInstanceOf(InitOnboardingCancelledError);
    expect(output.join('')).not.toContain('private-cancel-input');
  });

  it('uses ANSI styling only when color is enabled', async () => {
    const noColor = await run(['', '', '', '', ''], false);
    const color = await run(['', '', '', '', ''], true);

    expect(noColor.output).not.toContain('\u001b');
    expect(color.output).toContain('\u001b[');
  });

  it('renders a static completion handoff with color and without color', () => {
    const enteredRoutingValues = [
      'private-database-name',
      'private-collection-name',
      'C:\\private\\portable.key',
    ];
    const plain: string[] = [];
    const colored: string[] = [];
    writeInitOnboardingComplete({
      write: (text) => plain.push(text),
    });
    writeInitOnboardingComplete({
      color: true,
      write: (text) => colored.push(text),
    });

    const plainOutput = plain.join('');
    const coloredOutput = colored.join('');
    expect(plainOutput).toContain('SETUP COMPLETE');
    expect(plainOutput).toContain('[OK] Vault');
    expect(plainOutput).toContain('[OK] Datastore');
    expect(plainOutput).toContain('[OK] Portable key');
    expect(plainOutput).toContain('[!] Recovery not configured');
    expect(plainOutput).toContain('kavrix recovery create');
    expect(plainOutput).toContain('kavrix put <name>');
    expect(plainOutput).toContain('kavrix list');
    expect(plainOutput).toContain('separate secure locations');
    expect(plainOutput).not.toContain('\u001b');
    expect(coloredOutput).toContain('\u001b[');
    for (const enteredValue of enteredRoutingValues) {
      expect(plainOutput).not.toContain(enteredValue);
      expect(coloredOutput).not.toContain(enteredValue);
    }
  });
});
