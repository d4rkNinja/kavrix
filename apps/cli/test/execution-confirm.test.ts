import { Readable } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { requestApproval } from '../src/execution/confirm.js';

const ORIGINAL_STDERR_IS_TTY = process.stderr.isTTY;
const ORIGINAL_STDIN = process.stdin;
const ORIGINAL_STDERR_WRITE = process.stderr.write;

function withInteractiveStdin(input: string): void {
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Object.assign(Readable.from(input.length === 0 ? [] : [input]), {
      isTTY: true,
    }),
  });
  Object.defineProperty(process.stderr, 'isTTY', {
    configurable: true,
    value: true,
  });
}

beforeEach(() => {
  // Keep approval prompts out of the runner's own captured output.
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  process.stderr.write = ORIGINAL_STDERR_WRITE;
  Object.defineProperty(process.stderr, 'isTTY', {
    configurable: true,
    value: ORIGINAL_STDERR_IS_TTY,
  });
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: ORIGINAL_STDIN,
  });
});

describe('requestApproval', () => {
  it('grants on an explicit yes from the terminal', async () => {
    withInteractiveStdin('y\n');
    const outcome = await requestApproval({
      actor: 'agent',
      secret: 'github/token',
      executable: 'node',
      argumentsPreview: ['-e', 'code'],
    });
    expect(outcome).toBe('granted');
  });

  it('accepts the long spelling and treats anything else as declined', async () => {
    withInteractiveStdin('YES\n');
    expect(
      await requestApproval({ actor: 'user', executable: 'x', argumentsPreview: [] }),
    ).toBe('granted');

    withInteractiveStdin('n\n');
    expect(
      await requestApproval({ actor: 'user', executable: 'x', argumentsPreview: [] }),
    ).toBe('declined');
  });

  it('fails closed when no interactive terminal is attached', async () => {
    Object.defineProperty(process.stderr, 'isTTY', {
      configurable: true,
      value: false,
    });
    const outcome = await requestApproval({
      actor: 'agent',
      executable: 'x',
      argumentsPreview: [],
    });
    expect(outcome).toBe('unavailable');
  });

  it('treats a broken answer stream as a decline', async () => {
    withInteractiveStdin('');
    // An empty stream ends immediately; readline's question never resolves
    // through user input and the promise rejects into the decline path.
    const outcome = await requestApproval({
      actor: 'agent',
      executable: 'x',
      argumentsPreview: [],
    });
    expect(['declined', 'unavailable']).toContain(outcome);
  });
});
