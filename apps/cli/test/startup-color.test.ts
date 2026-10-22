import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:module', () => ({ enableCompileCache: vi.fn() }));
vi.mock('../src/cli-main.js', () => ({}));

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('CLI startup color contract', () => {
  it.each(['', '1'])(
    'keeps NO_COLOR=%j effective without disabling warnings',
    async (noColor) => {
      vi.stubEnv('NO_COLOR', noColor);
      vi.stubEnv('FORCE_COLOR', '3');
      const emitWarning = process.emitWarning;
      const nodeNoWarnings = process.env['NODE_NO_WARNINGS'];
      await import('../src/bin.js');
      expect(process.env['NO_COLOR']).toBe(noColor);
      expect(process.env['FORCE_COLOR']).toBeUndefined();
      expect(process.emitWarning).toBe(emitWarning);
      expect(process.env['NODE_NO_WARNINGS']).toBe(nodeNoWarnings);
    },
  );

  it('preserves an explicit FORCE_COLOR when NO_COLOR is absent', async () => {
    vi.stubEnv('NO_COLOR', undefined);
    vi.stubEnv('FORCE_COLOR', '3');
    await import('../src/bin.js');
    expect(process.env['FORCE_COLOR']).toBe('3');
  });
});
