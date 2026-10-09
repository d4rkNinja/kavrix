/**
 * Release guard: every source module under `apps/cli/src` must appear in both
 * `tsconfig.build.json` and `tsconfig.json` `include` lists.
 *
 * The list is explicit, so a new file that is not added is never compiled — and
 * `tsc -b`, `tsc -p`, and `eslint` all still report success because they are not
 * looking at it. That failure mode is invisible to every gate the repository
 * already runs, which is exactly why it needs its own. Exit non-zero on any
 * missing entry so CI cannot pass a package with an unreachable command.
 */
import { readFile } from 'node:fs/promises';
import { readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const packageDirectory = resolve(here, '..');
const cliDirectory = join(packageDirectory, 'apps', 'cli');

async function includedFiles(configPath) {
  const raw = await readFile(configPath, 'utf8');
  // tsconfig.json files here carry a UTF-8 BOM, which `JSON.parse` rejects.
  const parsed = JSON.parse(raw.replace(/^\uFEFF/, ''));
  const includes = Array.isArray(parsed.include) ? parsed.include : [];
  return new Set(
    includes
      .filter((entry) => typeof entry === 'string' && entry.startsWith('src/'))
      .map((entry) => entry.replace(/^src\//, '')),
  );
}

const [buildFiles, checkFiles] = await Promise.all([
  includedFiles(join(cliDirectory, 'tsconfig.build.json')),
  includedFiles(join(cliDirectory, 'tsconfig.json')),
]);

/** Walks the source tree without touching node_modules or dist. */
function walk(directory, prefix = '') {
  const found = [];
  for (const name of readdirSync(directory)) {
    if (name === 'node_modules' || name === 'dist') continue;
    const full = join(directory, name);
    const relative = prefix === '' ? name : `${prefix}/${name}`;
    if (statSync(full).isDirectory()) {
      found.push(...walk(full, relative));
    } else if (name.endsWith('.ts') || name.endsWith('.tsx')) {
      found.push(relative);
    }
  }
  return found;
}

const sources = walk(join(cliDirectory, 'src')).sort();
const problems = [];
for (const source of sources) {
  if (!buildFiles.has(source))
    problems.push(`tsconfig.build.json is missing src/${source}`);
  if (!checkFiles.has(source)) problems.push(`tsconfig.json is missing src/${source}`);
}

if (problems.length > 0) {
  console.error('A source file is not in both apps/cli tsconfig include lists.');
  console.error(
    'It is never compiled, so it cannot ship, yet every gate still passes.',
  );
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}

console.log(
  `ok ${String(sources.length)} source files are in both apps/cli include lists`,
);
