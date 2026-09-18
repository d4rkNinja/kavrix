import { PassThrough } from 'node:stream';

import { createElement } from 'react';
import { render, renderToString, Text } from 'ink';
import chalk from 'chalk';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { SplashGate } from '../src/splash-gate.js';
import {
  SplashScreen,
  SPLASH_ASCII_SPINNER_FRAMES,
  SPLASH_MAX_MS,
  SPLASH_MIN_MS,
  SPLASH_SPINNER_FRAMES,
  shouldDismissSplash,
  splashEnabled,
} from '../src/splash.js';

class TestOutput extends PassThrough {
  columns = 100;
  rows = 28;
  readonly isTTY = true;
}

function stripAnsi(value: string): string {
  // eslint-disable-next-line no-control-regex -- ANSI escape sequences are exactly what is being stripped
  return value.replace(/\u001b\[[0-9;?]*[A-Za-z]/g, '');
}

describe('splash helpers', () => {
  it('enables splash by default and respects KAVRIX_TUI_NO_SPLASH / --no-splash', () => {
    expect(splashEnabled({ env: {} })).toBe(true);
    expect(splashEnabled({ noSplash: true, env: {} })).toBe(false);
    expect(splashEnabled({ env: { KAVRIX_TUI_NO_SPLASH: '1' } })).toBe(false);
    expect(splashEnabled({ env: { KAVRIX_TUI_NO_SPLASH: 'true' } })).toBe(false);
    expect(splashEnabled({ env: { KAVRIX_TUI_NO_SPLASH: '0' } })).toBe(true);
  });

  it('dismisses after ready+min or at max duration', () => {
    expect(shouldDismissSplash({ startedAtMs: 0, nowMs: 500, ready: true })).toBe(
      false,
    );
    expect(
      shouldDismissSplash({
        startedAtMs: 0,
        nowMs: SPLASH_MIN_MS,
        ready: false,
      }),
    ).toBe(false);
    expect(
      shouldDismissSplash({
        startedAtMs: 0,
        nowMs: SPLASH_MIN_MS,
        ready: true,
      }),
    ).toBe(true);
    expect(
      shouldDismissSplash({
        startedAtMs: 0,
        nowMs: SPLASH_MAX_MS,
        ready: false,
      }),
    ).toBe(true);
  });
});

describe('SplashScreen', () => {
  const originalChalkLevel = chalk.level;

  afterEach(() => {
    chalk.level = originalChalkLevel;
  });

  it('renders dual-tone wordmark, tagline, and version', () => {
    const frame = renderToString(
      createElement(SplashScreen, {
        color: false,
        ascii: false,
        version: '0.2.13',
        animate: false,
        width: 100,
        height: 28,
      }),
      { columns: 100 },
    );
    expect(frame).toContain('local-first secrets firewall');
    expect(frame).toContain('v0.2.13');
    expect(frame).toMatch(/██/);
  });

  it('uses ASCII wordmark and |/-\\ spinner frames in ascii mode', () => {
    const frame = renderToString(
      createElement(SplashScreen, {
        color: false,
        ascii: true,
        version: '0.2.13',
        animate: false,
        width: 100,
        height: 28,
      }),
      { columns: 100 },
    );
    expect(frame).not.toMatch(/[█╔╗╚╝║═]/u);
    expect(frame).toContain('K   K');
    expect(frame).toContain('RRRR');
    expect(SPLASH_ASCII_SPINNER_FRAMES).toEqual(['|', '/', '-', '\\']);
    expect(SPLASH_SPINNER_FRAMES.some((f) => f === '\u280b')).toBe(true);
    expect(frame).toContain('|');
  });

  it('repaints while mounted (color cycle / spinner)', async () => {
    chalk.level = 1;
    const stdout = new TestOutput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));

    const instance = render(
      createElement(SplashScreen, {
        color: true,
        ascii: false,
        version: '0.2.13',
        width: 100,
        height: 28,
      }),
      {
        stdout: stdout as unknown as NodeJS.WriteStream,
        interactive: true,
        exitOnCtrlC: false,
        patchConsole: false,
      },
    );
    await instance.waitUntilRenderFlush();
    const first = Buffer.concat(chunks).length;
    await vi.waitFor(
      () => {
        expect(Buffer.concat(chunks).length).toBeGreaterThan(first);
      },
      { timeout: 2_000, interval: 40 },
    );
    instance.unmount();
    await instance.waitUntilExit();
    expect(stripAnsi(Buffer.concat(chunks).toString('utf8'))).toContain(
      'local-first secrets firewall',
    );
  });
});

describe('SplashGate', () => {
  it('shows splash then dismisses to children once ready and min elapsed', async () => {
    const stdout = new TestOutput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    const home = createElement(Text, null, 'HOME_READY');
    let now = 0;
    const clock = (): number => now;

    const instance = render(
      createElement(SplashGate, {
        color: false,
        ascii: true,
        version: '0.2.13',
        width: 80,
        height: 24,
        ready: false,
        now: clock,
        children: home,
      }),
      {
        stdout: stdout as unknown as NodeJS.WriteStream,
        interactive: true,
        exitOnCtrlC: false,
        patchConsole: false,
      },
    );
    await instance.waitUntilRenderFlush();
    let painted = stripAnsi(Buffer.concat(chunks).toString('utf8'));
    expect(painted).toContain('K   K');
    expect(painted).not.toContain('HOME_READY');

    // Past min but not ready — still splash
    now = SPLASH_MIN_MS;
    await new Promise((r) => setTimeout(r, 80));
    painted = stripAnsi(Buffer.concat(chunks).toString('utf8'));
    expect(painted).not.toContain('HOME_READY');

    instance.rerender(
      createElement(SplashGate, {
        color: false,
        ascii: true,
        version: '0.2.13',
        width: 80,
        height: 24,
        ready: true,
        now: clock,
        children: home,
      }),
    );
    now = SPLASH_MIN_MS + 20;
    await vi.waitFor(
      () => {
        const text = stripAnsi(Buffer.concat(chunks).toString('utf8'));
        expect(text).toContain('HOME_READY');
      },
      { timeout: 2_000, interval: 40 },
    );

    instance.unmount();
    await instance.waitUntilExit();
  });

  it('skips splash when noSplash is set', async () => {
    const stdout = new TestOutput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    const home = createElement(Text, null, 'HOME_NOSPLASH');
    const instance = render(
      createElement(SplashGate, {
        color: false,
        ascii: true,
        width: 80,
        height: 24,
        ready: false,
        noSplash: true,
        children: home,
      }),
      {
        stdout: stdout as unknown as NodeJS.WriteStream,
        interactive: true,
        exitOnCtrlC: false,
        patchConsole: false,
      },
    );
    await instance.waitUntilRenderFlush();
    const painted = stripAnsi(Buffer.concat(chunks).toString('utf8'));
    expect(painted).toContain('HOME_NOSPLASH');
    expect(painted).not.toContain('K   K');
    instance.unmount();
    await instance.waitUntilExit();
  });
});
