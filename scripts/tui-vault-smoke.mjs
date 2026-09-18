#!/usr/bin/env node
/**
 * Wrapper: runs the TypeScript smoke via tsx so CliTuiSession can be imported
 * from apps/cli/src (dist bundles it only into bin.js).
 */
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const tsxBin = join(root, 'node_modules/.bin/tsx');
const script = join(root, 'scripts/tui-vault-smoke.ts');

const child = spawn(tsxBin, [script], {
  stdio: 'inherit',
  env: process.env,
  windowsHide: true,
});
child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
