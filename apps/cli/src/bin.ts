#!/usr/bin/env node

/**
 * The executable entry point stays deliberately tiny: it enables the V8 module
 * compile cache before any application module is resolved, then defers the
 * entire CLI graph behind one dynamic import. Every subsequent `kavrix`
 * invocation reuses the on-disk code cache for the whole bundled module graph,
 * which removes most of the parse cost of a multi-megabyte bundle from warm
 * runs, and `--version`-style invocations never evaluate the heavy library
 * graph at all unless the command dispatch needs it.
 *
 * `enableCompileCache()` defaults to a cache directory under `os.tmpdir()`,
 * validates cached artifacts against the exact source bytes, and degrades to
 * normal compilation when the cache cannot be written, so this cannot serve
 * stale or tampered code and never blocks a run.
 */
import { enableCompileCache } from 'node:module';

// Kavrix honors NO_COLOR. Normalize conflicting inherited color flags before
// application imports initialize Node's color-aware console or terminal UI.
// This avoids Node's precedence warning without suppressing unrelated warnings.
if (process.env['NO_COLOR'] !== undefined) {
  delete process.env['FORCE_COLOR'];
}

enableCompileCache();

await import('./cli-main.js');
