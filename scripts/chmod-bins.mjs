// npm "build" helper: mark the CLI entry points executable (no-op on Windows).
import { chmodSync } from 'fs';
for (const f of ['cli', 'server', 'guard-bin']) chmodSync(`dist/${f}.js`, 0o755);
