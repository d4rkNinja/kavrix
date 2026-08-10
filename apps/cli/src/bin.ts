#!/usr/bin/env node

import { runPublicCli, productionRuntime } from './cli.js';

const runtime = productionRuntime();
const exitCode = await runPublicCli(process.argv.slice(2), runtime);
process.exitCode = exitCode;
