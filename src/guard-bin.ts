#!/usr/bin/env node
import { main } from './guard.js';

main().catch(err => {
  process.stderr.write(`tresor-guard: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2); // blocking error: fail closed
});
