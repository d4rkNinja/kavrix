import { describe, expect, it } from 'vitest';

import {
  InitOnboardingCancelledError,
  InitOnboardingDestinationError,
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
  it('renders every destination validation category and retries only that step', async () => {
    const answers = ['', ...Array.from({ length: 16 }, () => '')];
    const failures = [
      'unsafe-default-directory',
      'unsafe-key-file',
      'invalid-database',
      'invalid-collection',
      'invalid-destination',
    ] as const;
    let attempts = 0;
    let answerIndex = 0;
    const output: string[] = [];
    const result = await runInitOnboarding({
      question: async () => answers[answerIndex++] ?? '',
      selectStorage: async () => 'mongodb',
      validateDestination: async (patch) => {
        const failure = failures[attempts++];
        if (failure !== undefined) throw new InitOnboardingDestinationError(failure);
        return patch;
      },
      write: (text) => output.push(text),
    });

    expect(result.datastore).toBe('mongodb');
    expect(attempts).toBe(6);
    const transcript = output.join('');
    expect(transcript).toContain('could not safely use its protected default');
    expect(transcript).toContain('portable-key path is not private enough');
    expect(transcript).toContain('database name is invalid');
    expect(transcript).toContain('collection name is invalid');
    expect(transcript).toContain('Those destinations are not safe to use');
    expect(transcript.match(/STEP 1 \/ WELCOME & SECURITY/gu)).toHaveLength(1);
    expect(transcript.match(/STEP 3 \/ MONGODB DESTINATION/gu)).toHaveLength(6);
  });

  it('supports back and cancel from interactive storage selection', async () => {
    let selections = 0;
    const result = await runInitOnboarding({
      question: async () => '',
      selectStorage: async () => {
        selections += 1;
        return selections === 1 ? 'back' : 'file';
      },
      write: () => undefined,
    });
    expect(result.datastore).toBe('file');

    await expect(
      runInitOnboarding({
        question: async () => '',
        selectStorage: async () => 'cancel',
        write: () => undefined,
      }),
    ).rejects.toBeInstanceOf(InitOnboardingCancelledError);
  });

  it('supports field-level backtracking and protect-step correction without restarting', async () => {
    const mongodb = await run([
      '',
      '2',
      'first-db',
      'b',
      'second-db',
      'first-collection',
      'b',
      'second-collection',
      'first.key',
      'continue-too-soon',
      'b',
      'final-db',
      'final-collection',
      'final.key',
      '',
    ]);
    expect(mongodb.result).toEqual({
      datastore: 'mongodb',
      database: 'final-db',
      collection: 'final-collection',
      keyFile: 'final.key',
    });
    expect(mongodb.output).toContain('Press Enter to begin');
    expect(mongodb.output.match(/STEP 1 \/ WELCOME & SECURITY/gu)).toHaveLength(1);
    expect(mongodb.output.match(/STEP 3 \/ MONGODB DESTINATION/gu)).toHaveLength(2);

    const local = await run(['', '', 'first.data', 'b', 'final.data', 'final.key', '']);
    expect(local.result).toEqual({
      datastore: 'file',
      dataFile: 'final.data',
      keyFile: 'final.key',
    });
  });

  it('cancels safely from destination and protect steps', async () => {
    await expect(run(['', '', 'q'])).rejects.toBeInstanceOf(
      InitOnboardingCancelledError,
    );
    await expect(run(['', '', '', '', 'q'])).rejects.toBeInstanceOf(
      InitOnboardingCancelledError,
    );
  });

  it('treats a non-string question result as a safe blank value', async () => {
    let answers: unknown[] = [undefined, undefined, undefined, undefined, undefined];
    const result = await runInitOnboarding({
      question: async () => answers.shift() as string,
      write: () => undefined,
    });
    expect(result).toEqual({
      datastore: 'file',
      dataFile: './kavrix.vault',
      keyFile: './kavrix.key',
    });
  });

  it('does not swallow unexpected destination validation failures', async () => {
    const failure = new Error('unexpected validation failure');
    await expect(
      runInitOnboarding({
        question: async () => '',
        selectStorage: async () => 'file',
        validateDestination: async () => {
          throw failure;
        },
        write: () => undefined,
      }),
    ).rejects.toBe(failure);
  });

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
      profileHijackWarning: true,
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
    expect(plainOutput).toContain('use its stored default vault');
    expect(plainOutput).toContain('kavrix db vault use <id>');
    expect(plainOutput).toContain('separate secure locations');
    expect(plainOutput).not.toContain('\u001b');
    expect(coloredOutput).toContain('\u001b[');
    for (const enteredValue of enteredRoutingValues) {
      expect(plainOutput).not.toContain(enteredValue);
      expect(coloredOutput).not.toContain(enteredValue);
    }
  });
});
