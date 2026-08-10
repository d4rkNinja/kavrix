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

  it('renders a generic safe failure instead of an adapter error', async () => {
    const stdout = new TestOutput();
    const stdin = new TestInput();
    const failingListGroups = vi
      .fn<TuiUseCasePort['listGroups']>()
      .mockRejectedValue(new Error('PRIVATE-ADAPTER-ERROR'));
    const useCases: TuiUseCasePort = {
      listGroups: failingListGroups,
      listItems: vi.fn<TuiUseCasePort['listItems']>(),
      copyField: vi.fn<TuiUseCasePort['copyField']>(),
      authorizeReveal: vi.fn<TuiUseCasePort['authorizeReveal']>(),
      saveItem: vi.fn<TuiUseCasePort['saveItem']>(),
      lock: vi.fn<TuiUseCasePort['lock']>(),
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
  });
});
