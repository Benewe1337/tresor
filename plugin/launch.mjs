#!/usr/bin/env node
/**
 * Plugin entry point. The Claude Code plugin ships the prebuilt dist/ but not
 * node_modules; on first start this installs the runtime dependencies (including
 * the prebuilt native keyring binding for this OS) next to the plugin, then hands
 * over to dist/. Everything is logged to stderr — stdout belongs to MCP.
 *
 *   node launch.mjs server   → MCP server (default)
 *   node launch.mjs cli ...  → tresor CLI
 */

import { spawnSync } from 'child_process';
import { existsSync, mkdirSync, rmSync, statSync } from 'fs';
import { createRequire } from 'module';
import { dirname, join } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const RUNTIME_DEPS = ['@napi-rs/keyring', '@modelcontextprotocol/sdk/server/mcp.js', 'zod', 'cross-spawn'];
const LOCK = join(root, '.install-lock');
const LOCK_STALE_MS = 5 * 60_000;

function depsPresent() {
  const require = createRequire(join(root, 'package.json'));
  return RUNTIME_DEPS.every(d => { try { require.resolve(d); return true; } catch { return false; } });
}

function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function withLock(fn) {
  for (let i = 0; ; i++) {
    try { mkdirSync(LOCK); break; } catch {
      if (existsSync(LOCK) && Date.now() - statSync(LOCK).mtimeMs > LOCK_STALE_MS) rmSync(LOCK, { recursive: true, force: true });
      if (i > 600) throw new Error('tresor: timed out waiting for another dependency install');
      sleep(500);
    }
  }
  try { return fn(); } finally { rmSync(LOCK, { recursive: true, force: true }); }
}

function ensureDeps() {
  if (depsPresent()) return;
  withLock(() => {
    if (depsPresent()) return; // another process finished meanwhile
    process.stderr.write('[tresor] first start: installing runtime dependencies…\n');
    const r = spawnSync('npm', ['ci', '--omit=dev', '--no-audit', '--no-fund', '--loglevel=error'], {
      cwd: root,
      stdio: ['ignore', 2, 2], // keep stdout clean for the MCP protocol
      shell: process.platform === 'win32', // npm is npm.cmd on Windows; args are constant
    });
    if (r.status !== 0) throw new Error(`tresor: "npm ci" failed in ${root} (exit ${r.status}). Is npm on PATH?`);
  });
}

const mode = process.argv[2] ?? 'server';
const entry = { server: 'server.js', cli: 'cli.js' }[mode];
if (!entry) {
  process.stderr.write(`tresor launcher: unknown mode "${mode}" (server | cli)\n`);
  process.exit(2);
}
try {
  ensureDeps();
} catch (e) {
  process.stderr.write(`${e.message}\n`);
  process.exit(1);
}
process.argv.splice(2, 1); // the CLI sees its own arguments only
await import(pathToFileURL(join(root, 'dist', entry)).href);
