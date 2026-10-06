/**
 * Shared measurement helpers for the Kavrix performance suite.
 *
 * Every benchmark reports wall-clock milliseconds as a median over N
 * repetitions so that a single scheduler hiccup cannot masquerade as a
 * regression. Nothing in here observes, logs, or derives from secret material:
 * benchmarks only ever touch synthetic fixtures they create themselves.
 */
import { performance } from 'node:perf_hooks';

export function percentile(sorted, fraction) {
  if (sorted.length === 0) return Number.NaN;
  const index = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil(fraction * sorted.length) - 1),
  );
  return sorted[index];
}

export function summarize(samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  const mean = sorted.reduce((total, value) => total + value, 0) / sorted.length;
  return {
    runs: sorted.length,
    minMs: round(sorted[0]),
    medianMs: round(percentile(sorted, 0.5)),
    p95Ms: round(percentile(sorted, 0.95)),
    maxMs: round(sorted[sorted.length - 1]),
    meanMs: round(mean),
  };
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}

/** Measures the wall-clock cost of one async or sync operation. */
export async function measure(operation) {
  const started = performance.now();
  await operation();
  return performance.now() - started;
}

/**
 * Runs `operation` `iterations` times, discarding `warmup` leading samples so
 * JIT tiering and lazily initialized caches do not leak into the result.
 */
export async function timeRepeatedly(operation, { iterations, warmup = 0 }) {
  const samples = [];
  for (let index = 0; index < warmup; index += 1) {
    await operation();
  }
  for (let index = 0; index < iterations; index += 1) {
    samples.push(await measure(operation));
  }
  return summarize(samples);
}

/**
 * Measures steady-state throughput in operations per second.
 *
 * Sub-microsecond operations round to a zero median, so the mean is used as the
 * basis whenever the median rounds away. Reporting a null rate for a fast
 * operation would read as "no measurement" rather than "very fast".
 */
export async function throughput(operation, { iterations, warmup = 0 }) {
  const timing = await timeRepeatedly(operation, { iterations, warmup });
  const basisMs = timing.medianMs > 0 ? timing.medianMs : timing.meanMs;
  return {
    ...timing,
    basisMs: round(basisMs),
    opsPerSecond: basisMs > 0 ? Math.round(1e6 / basisMs) : null,
  };
}

/** Parses `--name=value` CLI arguments into a plain object. */
export function parseArgs(argv) {
  const values = {};
  for (const entry of argv) {
    const match = /^--([^=]+)=(.*)$/u.exec(entry);
    if (match !== null) values[match[1]] = match[2];
  }
  return values;
}
