import { PassThrough } from 'node:stream';

import {
  fieldDefinitionSchema,
  groupPayloadSchema,
  itemPayloadSchema,
} from '@kavrix/schemas';
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
  backupCodesField,
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

/**
 * Non-sensitive repeatable fixture so the editor rows render their values and
 * a Shift+Up/Down reorder is observable in the frame and in the saved draft.
 */
const reorderTimestamp = '2026-08-10T00:00:00.000Z';
const reorderField = fieldDefinitionSchema.parse({
  ...usernameField,
  id: 'field.reorder',
  stableKey: 'reorder_items',
  label: 'Reorder items',
  type: 'text',
  repeatable: true,
  sortOrder: 0,
});
const reorderGroup = groupPayloadSchema.parse({
  ...group,
  id: 'group.reorder',
  template: { ...group.template, id: 'template.reorder', fields: [reorderField] },
});
const reorderItem = itemPayloadSchema.parse({
  ...item,
  id: 'item.reorder',
  templateId: reorderGroup.template.id,
  templateValues: [
    {
      fieldId: reorderField.id,
      stableKey: reorderField.stableKey,
      value: {
        version: 1,
        state: 'present',
        content: {
          cardinality: 'multiple',
          elements: ['alpha', 'beta'].map((value, index) => ({
            id: `reorder.${String(index)}`,
            value: { kind: 'text' as const, value },
            lifecycle: { version: 1, status: 'available' as const },
          })),
        },
      },
      updatedAt: reorderTimestamp,
    },
  ],
});

function mountReorderFixture(): Readonly<{
  instance: ReturnType<typeof render>;
  listItems: ReturnType<typeof vi.fn<TuiUseCasePort['listItems']>>;
  saveItem: ReturnType<typeof vi.fn<TuiUseCasePort['saveItem']>>;
  lock: ReturnType<typeof vi.fn<TuiUseCasePort['lock']>>;
  stdin: TestInput;
  chunks: Buffer[];
}> {
  const stdout = new TestOutput();
  const stdin = new TestInput();
  const chunks: Buffer[] = [];
  stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
  const saveItem = vi
    .fn<TuiUseCasePort['saveItem']>()
    .mockImplementation((draft) => Promise.resolve({ status: 'saved', item: draft }));
  const lock = vi.fn<TuiUseCasePort['lock']>().mockResolvedValue();
  const listItems = vi
    .fn<TuiUseCasePort['listItems']>()
    .mockResolvedValue([reorderItem]);
  const useCases: TuiUseCasePort = {
    listGroups: vi.fn<TuiUseCasePort['listGroups']>().mockResolvedValue([reorderGroup]),
    listItems,
    copyField: vi.fn<TuiUseCasePort['copyField']>().mockResolvedValue(),
    authorizeReveal: vi.fn<TuiUseCasePort['authorizeReveal']>().mockResolvedValue(),
    saveItem,
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
  return { instance, listItems, saveItem, lock, stdin, chunks };
}

function savedElementValues(
  saveItem: ReturnType<typeof mountReorderFixture>['saveItem'],
): string[] {
  const item = saveItem.mock.calls[0]?.[0];
  const stored = item?.templateValues.find(
    (candidate) => candidate.fieldId === reorderField.id,
  );
  const value = stored?.value;
  if (value?.state !== 'present' || value.content.cardinality !== 'multiple') {
    return [];
  }
  return value.content.elements.map((element) =>
    element.value.kind === 'text' ? element.value.value : '<non-text>',
  );
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

    expect(screen).toContain('kavrix');
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
        {},
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
        {},
        expect.any(AbortSignal),
      );
    });

    for (const key of ['j', 'j', ']', 'c', 'y']) {
      stdin.write(key);
      await instance.waitUntilRenderFlush();
    }
    await vi.waitFor(() => {
      expect(copyField).toHaveBeenCalledWith(
        item.id,
        backupCodesField.id,
        { index: 2 },
        expect.any(AbortSignal),
      );
    });
    stdin.write('r');
    await vi.waitFor(() => {
      expect(authorizeReveal).toHaveBeenCalledWith(
        item.id,
        backupCodesField.id,
        { index: 2 },
        expect.any(AbortSignal),
      );
    });
    for (const key of ['k', 'k']) {
      stdin.write(key);
      await instance.waitUntilRenderFlush();
    }

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
    const lockedFrame = output.lastIndexOf('kavrix \u00b7 LOCKED');
    expect(lockedFrame).toBeGreaterThanOrEqual(0);
    expect(output.slice(lockedFrame)).not.toContain('PASSWORD-CANARY');
  });

  it('completes a confirm-policy repeatable reveal for only the selected element', async () => {
    const confirmField = fieldDefinitionSchema.parse({
      ...backupCodesField,
      revealPolicy: 'confirm',
    });
    const confirmGroup = groupPayloadSchema.parse({
      ...group,
      template: {
        ...group.template,
        fields: group.template.fields.map((field) =>
          field.id === confirmField.id ? confirmField : field,
        ),
      },
    });
    const stdout = new TestOutput();
    stdout.columns = 160;
    const stdin = new TestInput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    const authorizeReveal = vi
      .fn<TuiUseCasePort['authorizeReveal']>()
      .mockResolvedValue();
    const lock = vi.fn<TuiUseCasePort['lock']>().mockResolvedValue();
    const listItems = vi.fn<TuiUseCasePort['listItems']>().mockResolvedValue([item]);
    const useCases: TuiUseCasePort = {
      listGroups: vi
        .fn<TuiUseCasePort['listGroups']>()
        .mockResolvedValue([confirmGroup]),
      listItems,
      copyField: vi.fn<TuiUseCasePort['copyField']>().mockResolvedValue(),
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
      expect(listItems).toHaveBeenCalledWith(confirmGroup.id, expect.any(AbortSignal));
    });
    await instance.waitUntilRenderFlush();
    for (const key of ['\t', '\t', 'j', 'j', ']', 'r', 'y']) {
      stdin.write(key);
      await instance.waitUntilRenderFlush();
    }
    await vi.waitFor(() => {
      expect(authorizeReveal).toHaveBeenCalledWith(
        item.id,
        backupCodesField.id,
        { index: 2 },
        expect.any(AbortSignal),
      );
    });
    await instance.waitUntilRenderFlush();
    const output = Buffer.concat(chunks).toString('utf8');
    expect(output).toContain('[2]: code-b');
    expect(output).not.toContain('code-a');

    stdin.write('\u0003');
    await instance.waitUntilExit();
    expect(lock).toHaveBeenCalledOnce();
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
        {},
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
      {},
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

  it('reorders repeatable elements with Shift+Up in the editor', async () => {
    const { instance, listItems, saveItem, lock, stdin, chunks } =
      mountReorderFixture();
    await vi.waitFor(() => {
      expect(listItems).toHaveBeenCalledWith(reorderGroup.id, expect.any(AbortSignal));
    });
    await instance.waitUntilRenderFlush();

    for (const key of ['\t', '\t', 'e']) {
      stdin.write(key);
      await instance.waitUntilRenderFlush();
    }
    stdin.write('\u001b[B'); // Down: select the second element.
    await instance.waitUntilRenderFlush();
    chunks.length = 0;
    stdin.write('\u001b[1;2A'); // Shift+Up: reorder the selected element up.
    await instance.waitUntilRenderFlush();
    expect(Buffer.concat(chunks).toString('utf8')).toContain('1: beta');

    stdin.write('\r'); // Commit the reordered elements.
    await instance.waitUntilRenderFlush();
    stdin.write('s'); // Save the draft.
    await vi.waitFor(() => {
      expect(saveItem).toHaveBeenCalled();
    });
    expect(savedElementValues(saveItem)).toEqual(['beta', 'alpha']);

    stdin.write('l');
    await instance.waitUntilExit();
    expect(lock).toHaveBeenCalledOnce();
  });

  it('reorders repeatable elements with Shift+Down in the editor', async () => {
    const { instance, listItems, saveItem, lock, stdin } = mountReorderFixture();
    await vi.waitFor(() => {
      expect(listItems).toHaveBeenCalledWith(reorderGroup.id, expect.any(AbortSignal));
    });
    await instance.waitUntilRenderFlush();

    for (const key of ['\t', '\t', 'e']) {
      stdin.write(key);
      await instance.waitUntilRenderFlush();
    }
    stdin.write('\u001b[1;2B'); // Shift+Down: reorder the selected element down.
    await instance.waitUntilRenderFlush();
    stdin.write('\r'); // Commit the reordered elements.
    await instance.waitUntilRenderFlush();
    stdin.write('s'); // Save the draft.
    await vi.waitFor(() => {
      expect(saveItem).toHaveBeenCalled();
    });
    expect(savedElementValues(saveItem)).toEqual(['beta', 'alpha']);

    stdin.write('l');
    await instance.waitUntilExit();
    expect(lock).toHaveBeenCalledOnce();
  });
});
