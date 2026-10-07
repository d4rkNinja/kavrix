import { PassThrough } from 'node:stream';

import { createElement } from 'react';
import { render, Text } from 'ink';
import { describe, expect, it, vi } from 'vitest';

import { LoadingState, useListStagger } from '../../src/app/widgets.js';

class TestOutput extends PassThrough {
  columns = 80;
  rows = 24;
  readonly isTTY = true;
}

it('honors reduced motion while loading, including clock cleanup', async () => {
  vi.stubEnv('KAVRIX_TUI_REDUCED_MOTION', '1');
  const intervals = vi.spyOn(globalThis, 'setInterval');
  const stdout = new TestOutput();
  const instance = render(
    createElement(LoadingState, {
      label: 'Loading vault session...',
      color: false,
      ascii: true,
      animate: true,
    }),
    { stdout: stdout as unknown as NodeJS.WriteStream, patchConsole: false },
  );
  try {
    await instance.waitUntilRenderFlush();
    expect(intervals).not.toHaveBeenCalled();
  } finally {
    instance.unmount();
    await instance.waitUntilExit();
    intervals.mockRestore();
  }
});

describe('list stagger lifecycle', () => {
  it.each([0, 1, 4, 30])(
    'releases the idle clock for %i mounted rows',
    async (count) => {
      const clearTimer = vi.spyOn(globalThis, 'clearInterval');
      const intervals = vi.spyOn(globalThis, 'setInterval');
      let settled = false;
      function ListProbe(): ReturnType<typeof createElement> {
        const pending = useListStagger(count, true);
        settled = Array.from({ length: count }, (_, index) => pending(index)).every(
          (value) => !value,
        );
        return createElement(Text, null, settled ? 'settled' : 'entering');
      }
      const instance = render(createElement(ListProbe), {
        stdout: new TestOutput() as unknown as NodeJS.WriteStream,
        patchConsole: false,
      });
      try {
        await vi.waitFor(() => {
          expect(settled).toBe(true);
          if (count > 1) expect(clearTimer).toHaveBeenCalled();
          else expect(intervals).not.toHaveBeenCalled();
        });
      } finally {
        instance.unmount();
        await instance.waitUntilExit();
        clearTimer.mockRestore();
        intervals.mockRestore();
      }
    },
  );
});
