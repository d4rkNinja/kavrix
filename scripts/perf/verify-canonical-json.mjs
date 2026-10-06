/**
 * Differential check: the optimized canonical serializer must produce
 * byte-identical output to the original map/filter/join formulation for every
 * input, because its output is hashed into persisted digests.
 */
import { canonicalJson } from '../../packages/schemas/src/content-hash.ts';

/** The original implementation, verbatim. */
function reference(value) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('Canonical JSON rejects non-finite numbers.');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => reference(entry)).join(',')}]`;
  }
  if (typeof value !== 'object') {
    throw new TypeError('Canonical JSON accepts only JSON values.');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('Canonical JSON rejects non-plain objects.');
  }
  return `{${Object.keys(value)
    .sort()
    .filter((key) => value[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${reference(value[key])}`)
    .join(',')}}`;
}

/** Deterministic PRNG so a failure is reproducible. */
function makeRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

const KEY_ALPHABET = [
  'a',
  'Z',
  '0',
  '_',
  '$',
  '-',
  ' ',
  '"',
  '\\',
  '\n',
  '\t',
  'é',
  ' ',
  ' ',
  '😀',
  '',
];

function randomKey(random) {
  const length = Math.floor(random() * 6);
  let key = '';
  for (let index = 0; index < length; index += 1) {
    key += KEY_ALPHABET[Math.floor(random() * KEY_ALPHABET.length)];
  }
  return key;
}

function randomScalar(random) {
  const choice = Math.floor(random() * 10);
  if (choice === 0) return null;
  if (choice === 1) return true;
  if (choice === 2) return false;
  if (choice === 3) return 0;
  if (choice === 4) return -0;
  if (choice === 5) return 1.5e-300;
  if (choice === 6) return 1234567890123456789;
  if (choice === 7) return randomKey(random);
  if (choice === 8) return '';
  return Math.floor(random() * 1e6) / 7;
}

function randomValue(random, depth) {
  if (depth <= 0) return randomScalar(random);
  const choice = Math.floor(random() * 8);
  if (choice <= 4) return randomScalar(random);
  if (choice === 5) {
    const length = Math.floor(random() * 4);
    return Array.from({ length }, () => randomValue(random, depth - 1));
  }
  const entries = {};
  const count = Math.floor(random() * 5);
  for (let index = 0; index < count; index += 1) {
    const key = randomKey(random);
    // Include explicit undefined so the filter path is exercised, and insert in
    // deliberately unsorted key order.
    entries[key] = random() < 0.15 ? undefined : randomValue(random, depth - 1);
  }
  return entries;
}

let checked = 0;
let mismatches = 0;
const report = (label, value) => {
  let expected;
  let expectedError;
  try {
    expected = reference(value);
  } catch (error) {
    expectedError = error.message;
  }
  let actual;
  let actualError;
  try {
    actual = canonicalJson(value);
  } catch (error) {
    actualError = error.message;
  }
  checked += 1;
  const same = expectedError === actualError && expected === actual;
  if (!same) {
    mismatches += 1;
    if (mismatches <= 5) {
      console.log(`MISMATCH (${label})`);
      console.log('  input   ', JSON.stringify(value));
      console.log('  expected', expected ?? `ERROR:${expectedError}`);
      console.log('  actual  ', actual ?? `ERROR:${actualError}`);
    }
  }
};

// Fixed cases that must always agree.
report('null', null);
report('empty object', {});
report('empty array', []);
report('sorted keys', { a: 1, b: 2, c: 3 });
report('unsorted keys', { c: 3, a: 1, b: 2 });
report('undefined member', { a: 1, b: undefined, c: 3 });
report('all undefined', { a: undefined, b: undefined });
report('null prototype', Object.assign(Object.create(null), { b: 1, a: 2 }));
report('nested', { z: [{ b: 1, a: 2 }], a: { d: 4, c: 3 } });
report('escaped keys', { 'a"b': 1, 'a\\b': 2, 'a\nb': 3, é: 4 });
report('identifier keys', { simple: 1, _under: 2, $dollar: 3, a1: 4 });
report('empty key', { '': 1, a: 2 });
report('negative zero', { z: -0 });
report('deep', JSON.parse(JSON.stringify(buildNested(12, 'leaf'))));

const random = makeRandom(0x5eed);
for (let index = 0; index < 200_000; index += 1) {
  report(`random#${index}`, randomValue(random, 4));
}

// Rejections must still be rejections.
for (const rejected of [1n, () => {}, Symbol('s'), new Date(0), new Map()]) {
  report('reject', rejected);
}

function buildNested(depth, leaf) {
  if (depth <= 0) return { leaf };
  const value = {};
  for (let index = 0; index < 3; index += 1) {
    value[`k${index}`] = buildNested(depth - 1, leaf);
  }
  return value;
}

console.log(
  JSON.stringify({
    checked,
    mismatches,
    verdict: mismatches === 0 ? 'identical' : 'DIVERGED',
  }),
);
if (mismatches > 0) process.exitCode = 1;
