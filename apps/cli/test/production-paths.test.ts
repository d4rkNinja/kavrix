import { isAbsolute, join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { resolveCliDataPaths } from '../src/production/paths.js';

describe('production CLI data paths', () => {
  it('places the deterministic global writer lease below the resolved data home', () => {
    const home = isAbsolute('D:\\kavrix-test') ? 'D:\\kavrix-test' : '/tmp/kavrix-test';
    const paths = resolveCliDataPaths({ CREDS_HOME: home }, process.platform);

    expect(paths.writerLease).toBe(join(paths.home, 'cli.writer.lock'));
  });
});
