#!/usr/bin/env node
import { main } from './mcp.js';
main().catch(err => {
    process.stderr.write(`tresor-mcp: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
});
