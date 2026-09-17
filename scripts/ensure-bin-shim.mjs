import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readlinkSync,
  statSync,
  symlinkSync,
  unlinkSync,
} from 'node:fs';
import { dirname, relative } from 'node:path';
import { platform } from 'node:process';
import { fileURLToPath } from 'node:url';

function ensureBinShim() {
  if (platform === 'win32') return;

  const target = fileURLToPath(new URL('../apps/cli/dist/bin.js', import.meta.url));
  const targetStat = statSync(target, { throwIfNoEntry: false });
  if (!targetStat) return;
  if (!targetStat.isFile()) throw new Error('CLI bin target must be a file');

  const bin = fileURLToPath(new URL('../node_modules/.bin/kavrix', import.meta.url));
  const linkTarget = relative(dirname(bin), target);
  mkdirSync(dirname(bin), { recursive: true });
  chmodSync(target, targetStat.mode | 0o111);

  const existing = lstatSync(bin, { throwIfNoEntry: false });
  if (existing?.isSymbolicLink() && readlinkSync(bin) === linkTarget) return;
  if (existing) unlinkSync(bin);
  symlinkSync(linkTarget, bin);
}

ensureBinShim();
