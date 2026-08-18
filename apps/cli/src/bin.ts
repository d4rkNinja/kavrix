#!/usr/bin/env node

import { runLocalCli } from './local-vault-cli.js';

await runLocalCli(process.argv);
