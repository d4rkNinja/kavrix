#!/usr/bin/env node

import { runMongoApiService } from './service.js';

const exitCode = await runMongoApiService();
await new Promise<void>((resolve, reject) => {
  process.stderr.write('', (error) => {
    if (error === null || error === undefined) resolve();
    else reject(error);
  });
});
process.exit(exitCode);
