import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execPath, platform } from 'node:process';
import { test } from 'node:test';

test(
  'workspace bin creation, idempotency and repair',
  { skip: platform === 'win32' },
  () => {
    const root = mkdtempSync(join(tmpdir(), 'kavrix-bin-shim-'));
    try {
      mkdirSync(join(root, 'scripts'));
      const script = join(root, 'scripts/ensure-bin-shim.mjs');
      copyFileSync(new URL('./ensure-bin-shim.mjs', import.meta.url), script);
      const run = () => execFileSync(execPath, [script], { cwd: tmpdir() });
      const bin = join(root, 'node_modules/.bin/kavrix');
      const assertBin = () => {
        assert.ok(lstatSync(bin).isSymbolicLink());
        assert.equal(readlinkSync(bin), '../../apps/cli/dist/bin.js');
        assert.equal(execFileSync(bin, { encoding: 'utf8' }), 'workspace-bin\n');
      };

      run();
      assert.equal(existsSync(join(root, 'node_modules')), false);

      mkdirSync(join(root, 'apps/cli/dist'), { recursive: true });
      writeFileSync(
        join(root, 'apps/cli/dist/bin.js'),
        '#!/usr/bin/env node\nconsole.log("workspace-bin");\n',
        { mode: 0o644 },
      );
      run();
      assertBin();
      const inode = lstatSync(bin).ino;
      run();
      assertBin();
      assert.equal(lstatSync(bin).ino, inode);

      rmSync(bin);
      symlinkSync('../../missing-bin.js', bin);
      run();
      assertBin();

      rmSync(bin);
      writeFileSync(bin, 'stale shim');
      run();
      assertBin();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);
