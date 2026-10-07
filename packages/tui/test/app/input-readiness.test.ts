import { describe, expect, it } from 'vitest';
import { createInputReadiness } from '../../src/app/input-readiness.js';

describe('committed frame input readiness', () => {
  it('waits through pending resize and an interim paint until the changed frame commits', async () => {
    let frame = 0;
    const readiness = createInputReadiness(() => frame);
    readiness.painted();
    const release = readiness.hold();
    let ready = false;
    const waiting = readiness.wait().then(() => {
      ready = true;
    });
    readiness.painted();
    await Promise.resolve();
    expect(ready).toBe(false);
    frame += 1;
    release();
    release();
    await Promise.resolve();
    expect(ready).toBe(false);
    readiness.painted();
    await waiting;
    expect(ready).toBe(true);
  });
  it('waits for the current frame and waits again after navigation', async () => {
    let frame = 0;
    const readiness = createInputReadiness(() => frame);
    let ready = false;
    const first = readiness.wait().then(() => {
      ready = true;
    });
    await Promise.resolve();
    expect(ready).toBe(false);
    readiness.painted();
    await first;
    expect(ready).toBe(true);
    frame += 1;
    ready = false;
    const next = readiness.wait().then(() => {
      ready = true;
    });
    await Promise.resolve();
    expect(ready).toBe(false);
    readiness.painted();
    await next;
    expect(ready).toBe(true);
  });

  it('settles pending and future callers when the app is disposed', async () => {
    const readiness = createInputReadiness(() => 1);
    const pending = readiness.wait();
    readiness.dispose();
    await pending;
    await readiness.wait();
  });
});
