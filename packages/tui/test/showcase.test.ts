import { PassThrough } from 'node:stream';

import { createElement } from 'react';
import { render, renderToString } from 'ink';
import chalk from 'chalk';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  BrandBanner,
  StorageSelectionShowcase,
  mountStorageSelectionShowcase,
} from '../src/showcase.js';

class TestOutput extends PassThrough {
  columns = 100;
  rows = 24;
  readonly isTTY = true;
}

function stripAnsi(value: string): string {
  // eslint-disable-next-line no-control-regex -- ANSI escape sequences are exactly what is being stripped
  return value.replace(/\u001b\[[0-9;?]*[A-Za-z]/g, '');
}

function snapshot(
  props: Readonly<{
    selected: 'file' | 'mongodb';
    color?: boolean;
    ascii?: boolean;
  }>,
): string {
  return renderToString(createElement(StorageSelectionShowcase, props), {
    columns: 100,
  });
}

describe('storage selection showcase', () => {
  const originalChalkLevel = chalk.level;

  afterEach(() => {
    chalk.level = originalChalkLevel;
    vi.useRealTimers();
  });

  it('renders both storage backends and marks the highlighted row', () => {
    const fileFrame = snapshot({ selected: 'file' });
    const mongodbFrame = snapshot({ selected: 'mongodb' });

    expect(fileFrame).toContain('Local encrypted file');
    expect(fileFrame).toContain('MongoDB');
    expect(fileFrame).toContain('STEP 2 / STORAGE');
    expect(fileFrame).toContain('KAVRIX');
    expect(fileFrame).toContain('\u276f Local encrypted file');
    expect(fileFrame).not.toContain('\u276f MongoDB');
    expect(mongodbFrame).toContain('\u276f MongoDB');
    expect(mongodbFrame).not.toContain('\u276f Local encrypted file');
  });

  it('restricts glyphs to printable ASCII in fallback mode', () => {
    const frame = snapshot({ selected: 'file', ascii: true });

    expect(frame).not.toContain('\u276f');
    expect(frame).toContain('>');
    expect(frame).toContain('Up/Down navigate');
  });

  it('keeps every rendered value free of hostile escape sequences', () => {
    const frame = snapshot({ selected: 'mongodb', color: false });

    expect(frame).toContain('ciphertext stays beside you');
    expect(frame).not.toContain('\u0007');
    expect(frame).not.toContain('\u001b]');
  });

  it('repaints continuously and paints colored accents when enabled', async () => {
    chalk.level = 1;
    const stdout = new TestOutput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));

    const instance = render(createElement(BrandBanner, { color: true }), {
      stdout: stdout as unknown as NodeJS.WriteStream,
      interactive: true,
      exitOnCtrlC: false,
      patchConsole: false,
    });
    await instance.waitUntilRenderFlush();
    const firstPaintLength = Buffer.concat(chunks).length;
    await vi.waitFor(
      () => {
        expect(Buffer.concat(chunks).length).toBeGreaterThan(firstPaintLength);
      },
      { timeout: 2_000, interval: 50 },
    );
    instance.unmount();
    await instance.waitUntilExit();

    const painted = Buffer.concat(chunks).toString('utf8');
    expect(stripAnsi(painted)).toContain('KAVRIX');
    expect(painted).toMatch(/\u001b\[\d+m/); // eslint-disable-line no-control-regex -- asserting SGR color output
  });

  it('mounts, repaints on selection changes, and tears down cleanly', async () => {
    chalk.level = 0;
    const stdout = new TestOutput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));

    const showcase = mountStorageSelectionShowcase({
      stdout: stdout as unknown as NodeJS.WriteStream,
      color: false,
    });
    await new Promise((resolve) => setImmediate(resolve));
    showcase.select('mongodb');
    await new Promise((resolve) => setImmediate(resolve));
    await showcase.end();

    const painted = Buffer.concat(chunks).toString('utf8');
    expect(painted).toContain('Local encrypted file');
    expect(painted).toContain('MongoDB');
    // eslint-disable-next-line no-control-regex -- asserting no SGR color output
    expect(painted).not.toMatch(/\u001b\[\d+m/);
  });

  it('keeps color output when the caller enables styling', async () => {
    chalk.level = 1;
    const stdout = new TestOutput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));

    const showcase = mountStorageSelectionShowcase({
      stdout: stdout as unknown as NodeJS.WriteStream,
      color: true,
    });
    await new Promise((resolve) => setImmediate(resolve));
    await showcase.end();

    // eslint-disable-next-line no-control-regex -- asserting SGR color output
    expect(Buffer.concat(chunks).toString('utf8')).toMatch(/\u001b\[\d+m/);
  });
});
