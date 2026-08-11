import { PassThrough } from 'node:stream';

import { createElement } from 'react';
import { render, renderToString } from 'ink';
import { describe, expect, it, vi } from 'vitest';

import {
  DynamicSchemaBuilder,
  MultipleNoteEditor,
  TuiScreen,
  VaultTui,
} from '../src/components.js';
import type { TuiUseCasePort } from '../src/contracts.js';
import { createInitialTuiState, transitionTui, type TuiState } from '../src/state.js';
import {
  browserState,
  group,
  item,
  itemNotes,
  passwordField,
  secondItem,
  usernameField,
} from './fixtures.js';

class TestOutput extends PassThrough {
  columns = 80;
  rows = 24;
  readonly isTTY = true;
}

class TestInput extends PassThrough {
  readonly isTTY = true;
  isRaw = false;

  setRawMode(value: boolean): this {
    this.isRaw = value;
    return this;
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }
}

function hydratedState(): TuiState {
  let result = transitionTui(createInitialTuiState(), { type: 'start' });
  result = transitionTui(result.state, {
    type: 'groups-loaded',
    requestId: 1,
    groups: browserState().groups,
  });
  return transitionTui(result.state, {
    type: 'items-loaded',
    requestId: 2,
    groupId: group.id,
    items: browserState().items,
  }).state;
}

function deferred(): Readonly<{
  promise: Promise<void>;
  resolve: () => void;
}> {
  let resolvePromise: (() => void) | undefined;
  const promise = new Promise<void>((resolve) => {
    resolvePromise = resolve;
  });
  return {
    promise,
    resolve: () => resolvePromise?.(),
  };
}

describe('Ink components', () => {
  it('renders the screen, schema builder, and multiple-note editor through Ink', () => {
    const screen = renderToString(
      createElement(TuiScreen, { state: hydratedState(), nowMs: 0 }),
      { columns: 80 },
    );
    const schema = renderToString(
      createElement(DynamicSchemaBuilder, {
        fields: [passwordField, usernameField],
      }),
    );
    const notes = renderToString(
      createElement(MultipleNoteEditor, {
        notes: itemNotes,
        selectedIndex: 0,
      }),
    );
    const asciiNotes = renderToString(
      createElement(MultipleNoteEditor, {
        notes: itemNotes,
        selectedIndex: 1,
        ascii: true,
      }),
    );

    expect(screen).toContain('CredVault');
    expect(schema).toContain('Password [secret] masked (required, masked)');
    expect(schema).toContain('Username [username] single-line (required)');
    expect(notes).not.toContain('ITEM-NOTE-CANARY');
    expect(notes).toContain('Work mailbox');
    expect(asciiNotes).toContain('********');
  });

  it('composes the runtime port, processes keyboard input, resize, copy, save, and lock', async () => {
    const stdout = new TestOutput();
    const stdin = new TestInput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));

    const listGroups = vi.fn<TuiUseCasePort['listGroups']>().mockResolvedValue([group]);
    const listItems = vi.fn<TuiUseCasePort['listItems']>().mockResolvedValue([item]);
    const copyField = vi.fn<TuiUseCasePort['copyField']>().mockResolvedValue();
    const authorizeReveal = vi
      .fn<TuiUseCasePort['authorizeReveal']>()
      .mockResolvedValue();
    const saveItem = vi
      .fn<TuiUseCasePort['saveItem']>()
      .mockImplementation((draft) => Promise.resolve({ status: 'saved', item: draft }));
    const lock = vi.fn<TuiUseCasePort['lock']>().mockResolvedValue();
    const onLocked = vi.fn<() => void>();
    const useCases: TuiUseCasePort = {
      listGroups,
      listItems,
      copyField,
      authorizeReveal,
      saveItem,
      lock,
    };

    const instance = render(
      createElement(VaultTui, { useCases, now: () => 1_000, onLocked }),
      {
        stdout: stdout as unknown as NodeJS.WriteStream,
        stdin: stdin as unknown as NodeJS.ReadStream,
        interactive: true,
        exitOnCtrlC: false,
        patchConsole: false,
        maxFps: 1_000,
      },
    );

    await vi.waitFor(() => {
      expect(listGroups).toHaveBeenCalledOnce();
    });
    await vi.waitFor(() => {
      expect(listItems).toHaveBeenCalledWith(group.id, expect.any(AbortSignal));
    });
    await instance.waitUntilRenderFlush();

    stdin.write('\t');
    await instance.waitUntilRenderFlush();
    stdin.write('\t');
    await instance.waitUntilRenderFlush();
    stdin.write('j');
    await instance.waitUntilRenderFlush();
    expect(Buffer.concat(chunks).toString('utf8')).not.toContain('PASSWORD-CANARY');
    stdin.write('r');
    await vi.waitFor(() => {
      expect(authorizeReveal).toHaveBeenCalledWith(
        item.id,
        passwordField.id,
        expect.any(AbortSignal),
      );
    });
    stdin.write('k');
    await instance.waitUntilRenderFlush();
    stdin.write('c');
    await vi.waitFor(() => {
      expect(copyField).toHaveBeenCalledWith(
        item.id,
        usernameField.id,
        expect.any(AbortSignal),
      );
    });

    for (const key of ['e', 'x', '\r', 's']) {
      stdin.write(key);
      await instance.waitUntilRenderFlush();
    }
    await vi.waitFor(() => {
      expect(saveItem).toHaveBeenCalled();
    });
    expect(JSON.stringify(copyField.mock.calls)).not.toContain('PASSWORD-CANARY');

    stdout.columns = 60;
    stdout.rows = 20;
    stdout.emit('resize');
    await instance.waitUntilRenderFlush();

    stdin.write('l');
    await instance.waitUntilExit();
    expect(lock).toHaveBeenCalledOnce();
    expect(onLocked).toHaveBeenCalledOnce();
    expect(stdin.isRaw).toBe(false);
    const output = Buffer.concat(chunks).toString('utf8');
    const lockedFrame = output.lastIndexOf('CredVault \u00b7 LOCKED');
    expect(lockedFrame).toBeGreaterThanOrEqual(0);
    expect(output.slice(lockedFrame)).not.toContain('PASSWORD-CANARY');
  });

  it('carries item identity through a deferred reveal completion', async () => {
    const stdout = new TestOutput();
    const stdin = new TestInput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    const firstReveal = deferred();
    const authorizeReveal = vi
      .fn<TuiUseCasePort['authorizeReveal']>()
      .mockImplementationOnce(() => firstReveal.promise)
      .mockResolvedValueOnce();
    const lock = vi.fn<TuiUseCasePort['lock']>().mockResolvedValue();
    const listItems = vi
      .fn<TuiUseCasePort['listItems']>()
      .mockResolvedValue([item, secondItem]);
    const useCases: TuiUseCasePort = {
      listGroups: vi.fn<TuiUseCasePort['listGroups']>().mockResolvedValue([group]),
      listItems,
      copyField: vi.fn<TuiUseCasePort['copyField']>(),
      authorizeReveal,
      saveItem: vi.fn<TuiUseCasePort['saveItem']>(),
      lock,
    };
    const instance = render(createElement(VaultTui, { useCases, now: () => 1_000 }), {
      stdout: stdout as unknown as NodeJS.WriteStream,
      stdin: stdin as unknown as NodeJS.ReadStream,
      interactive: true,
      exitOnCtrlC: false,
      patchConsole: false,
      maxFps: 1_000,
    });
    await vi.waitFor(() => {
      expect(listItems).toHaveBeenCalledOnce();
    });

    for (const key of ['\t', '\t', 'j', 'r']) {
      stdin.write(key);
      await instance.waitUntilRenderFlush();
    }
    await vi.waitFor(() => {
      expect(authorizeReveal).toHaveBeenNthCalledWith(
        1,
        item.id,
        passwordField.id,
        expect.any(AbortSignal),
      );
    });

    for (const key of ['\t', '\t', 'j']) {
      stdin.write(key);
      await instance.waitUntilRenderFlush();
    }
    firstReveal.resolve();
    await instance.waitUntilRenderFlush();
    expect(Buffer.concat(chunks).toString('utf8')).not.toContain('PASSWORD-CANARY');

    stdin.write('\t');
    await instance.waitUntilRenderFlush();
    stdin.write('j');
    await instance.waitUntilRenderFlush();
    stdin.write('r');
    await vi.waitFor(() => {
      expect(authorizeReveal).toHaveBeenCalledTimes(2);
    });
    await instance.waitUntilRenderFlush();
    expect(authorizeReveal).toHaveBeenNthCalledWith(
      2,
      secondItem.id,
      passwordField.id,
      expect.any(AbortSignal),
    );
    expect(Buffer.concat(chunks).toString('utf8')).toContain('PASSWORD-CANARY');

    stdin.write('l');
    await instance.waitUntilExit();
    expect(lock).toHaveBeenCalledOnce();
  });

  it('does not exit after a failed lock and exits once after a confirmed retry', async () => {
    const stdout = new TestOutput();
    const stdin = new TestInput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    const lock = vi
      .fn<TuiUseCasePort['lock']>()
      .mockRejectedValueOnce(new Error('PRIVATE-LOCK-ERROR'))
      .mockResolvedValueOnce();
    const onLocked = vi.fn<() => void>();
    const listItems = vi.fn<TuiUseCasePort['listItems']>().mockResolvedValue([item]);
    const useCases: TuiUseCasePort = {
      listGroups: vi.fn<TuiUseCasePort['listGroups']>().mockResolvedValue([group]),
      listItems,
      copyField: vi.fn<TuiUseCasePort['copyField']>(),
      authorizeReveal: vi.fn<TuiUseCasePort['authorizeReveal']>(),
      saveItem: vi.fn<TuiUseCasePort['saveItem']>(),
      lock,
    };
    const instance = render(createElement(VaultTui, { useCases, onLocked }), {
      stdout: stdout as unknown as NodeJS.WriteStream,
      stdin: stdin as unknown as NodeJS.ReadStream,
      interactive: true,
      exitOnCtrlC: false,
      patchConsole: false,
      maxFps: 1_000,
    });
    await vi.waitFor(() => {
      expect(listItems).toHaveBeenCalledOnce();
    });

    stdin.write('l');
    await vi.waitFor(() => {
      expect(lock).toHaveBeenCalledTimes(1);
    });
    await vi.waitFor(() => {
      expect(Buffer.concat(chunks).toString('utf8')).toContain(
        'Operation failed safely',
      );
    });
    expect(onLocked).not.toHaveBeenCalled();
    expect(Buffer.concat(chunks).toString('utf8')).not.toContain('PRIVATE-LOCK-ERROR');

    stdin.write('\x03');
    await instance.waitUntilExit();
    expect(lock).toHaveBeenCalledTimes(2);
    expect(onLocked).toHaveBeenCalledOnce();
  });

  it('locks from an initial-load error and on caller-driven unmount', async () => {
    const stdout = new TestOutput();
    const stdin = new TestInput();
    const lockAfterLoadFailure = vi.fn<TuiUseCasePort['lock']>().mockResolvedValue();
    const failingListGroups = vi
      .fn<TuiUseCasePort['listGroups']>()
      .mockRejectedValue(new Error('PRIVATE-LOAD-ERROR'));
    const failingUseCases: TuiUseCasePort = {
      listGroups: failingListGroups,
      listItems: vi.fn<TuiUseCasePort['listItems']>(),
      copyField: vi.fn<TuiUseCasePort['copyField']>(),
      authorizeReveal: vi.fn<TuiUseCasePort['authorizeReveal']>(),
      saveItem: vi.fn<TuiUseCasePort['saveItem']>(),
      lock: lockAfterLoadFailure,
    };
    const failedInstance = render(
      createElement(VaultTui, { useCases: failingUseCases }),
      {
        stdout: stdout as unknown as NodeJS.WriteStream,
        stdin: stdin as unknown as NodeJS.ReadStream,
        interactive: true,
        exitOnCtrlC: false,
        patchConsole: false,
        maxFps: 1_000,
      },
    );
    await vi.waitFor(() => {
      expect(failingListGroups).toHaveBeenCalledOnce();
    });
    stdin.write('\x03');
    await failedInstance.waitUntilExit();
    expect(lockAfterLoadFailure).toHaveBeenCalledOnce();

    const unmountLock = vi
      .fn<TuiUseCasePort['lock']>()
      .mockRejectedValue(new Error('PRIVATE-UNMOUNT-LOCK-ERROR'));
    const onCleanupLockFailed = vi.fn<() => void>();
    const unmountListItems = vi
      .fn<TuiUseCasePort['listItems']>()
      .mockResolvedValue([item]);
    const unmountUseCases: TuiUseCasePort = {
      ...failingUseCases,
      listGroups: vi.fn<TuiUseCasePort['listGroups']>().mockResolvedValue([group]),
      listItems: unmountListItems,
      lock: unmountLock,
    };
    const unmounted = render(
      createElement(VaultTui, { useCases: unmountUseCases, onCleanupLockFailed }),
      {
        stdout: new TestOutput() as unknown as NodeJS.WriteStream,
        stdin: new TestInput() as unknown as NodeJS.ReadStream,
        interactive: true,
        exitOnCtrlC: false,
        patchConsole: false,
      },
    );
    await vi.waitFor(() => {
      expect(unmountListItems).toHaveBeenCalledOnce();
    });
    unmounted.unmount();
    await unmounted.waitUntilExit();
    await vi.waitFor(() => {
      expect(unmountLock).toHaveBeenCalledOnce();
    });
    await vi.waitFor(() => {
      expect(onCleanupLockFailed).toHaveBeenCalledOnce();
    });
    expect(onCleanupLockFailed).toHaveBeenCalledWith();
    expect(JSON.stringify(onCleanupLockFailed.mock.calls)).not.toContain('PRIVATE');
  });

  it('renders a generic safe failure instead of an adapter error', async () => {
    const stdout = new TestOutput();
    const stdin = new TestInput();
    const failingListGroups = vi
      .fn<TuiUseCasePort['listGroups']>()
      .mockRejectedValue(new Error('PRIVATE-ADAPTER-ERROR'));
    const lock = vi.fn<TuiUseCasePort['lock']>().mockResolvedValue();
    const useCases: TuiUseCasePort = {
      listGroups: failingListGroups,
      listItems: vi.fn<TuiUseCasePort['listItems']>(),
      copyField: vi.fn<TuiUseCasePort['copyField']>(),
      authorizeReveal: vi.fn<TuiUseCasePort['authorizeReveal']>(),
      saveItem: vi.fn<TuiUseCasePort['saveItem']>(),
      lock,
    };
    const instance = render(createElement(VaultTui, { useCases }), {
      stdout: stdout as unknown as NodeJS.WriteStream,
      stdin: stdin as unknown as NodeJS.ReadStream,
      interactive: false,
      patchConsole: false,
    });

    await vi.waitFor(() => {
      expect(failingListGroups).toHaveBeenCalledOnce();
    });
    instance.unmount();
    await instance.waitUntilExit();
    await vi.waitFor(() => {
      expect(lock).toHaveBeenCalledOnce();
    });
  });
});
