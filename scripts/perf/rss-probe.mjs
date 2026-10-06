/**
 * Reports the resident set the CLI actually reaches at exit, written by a
 * preload that samples `process.memoryUsage()` on the `exit` hook.
 */
import { writeFileSync } from 'node:fs';

const target = process.env.KAVRIX_PERF_RSS_FILE;
if (target !== undefined && target !== '') {
  process.on('exit', () => {
    try {
      writeFileSync(target, String(Math.round(process.memoryUsage().rss)));
    } catch {
      // A failed measurement must never change CLI behavior.
    }
  });
}
