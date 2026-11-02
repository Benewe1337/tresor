/**
 * Injection operations used by the MCP server. Every result that goes back to the
 * caller is passed through the Redactor first; secret values never leave here.
 */

import { spawn } from 'child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { writtenFilesPath } from './paths.js';
import { Redactor, truncate } from './redact.js';
import type { SecretStore } from './store.js';
import { fill, placeholderNames } from './template.js';

export const DEFAULT_TIMEOUT_MS = 120_000;
export const MAX_OUTPUT_CHARS = 40_000;
const MAX_CAPTURE_BYTES = 10 * 1024 * 1024;

function resolveMany(store: SecretStore, names: string[]): Record<string, string> {
  return Object.fromEntries(names.map(n => [n, store.resolve(n)]));
}

export interface RunInput {
  command: string[];
  /** ENV_VAR → secret name */
  env?: Record<string, string>;
  cwd?: string;
  timeoutMs?: number;
}

export interface RunResult {
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
}

export async function runWithSecrets(store: SecretStore, input: RunInput): Promise<RunResult> {
  if (input.command.length === 0) throw new Error('command must not be empty');
  const envMap = input.env ?? {};
  const argNames = placeholderNames(...input.command);
  const values = resolveMany(store, [...new Set([...Object.values(envMap), ...argNames])]);
  const redactor = new Redactor(values);

  const childEnv: NodeJS.ProcessEnv = { ...process.env };
  for (const [envVar, name] of Object.entries(envMap)) childEnv[envVar] = values[name];
  const [cmd, ...args] = input.command.map(a => fill(a, values));

  return new Promise((res, rej) => {
    const proc = spawn(cmd, args, {
      env: childEnv,
      cwd: input.cwd ?? process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const chunks = { stdout: [] as Buffer[], stderr: [] as Buffer[] };
    let captured = 0;
    const collect = (key: 'stdout' | 'stderr') => (d: Buffer) => {
      if (captured >= MAX_CAPTURE_BYTES) return;
      captured += d.length;
      chunks[key].push(d);
    };
    proc.stdout.on('data', collect('stdout'));
    proc.stderr.on('data', collect('stderr'));

    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; proc.kill('SIGTERM'); }, input.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    proc.on('error', err => { clearTimeout(timer); rej(new Error(redactor.redact(err.message))); });
    proc.on('close', (code, signal) => {
      clearTimeout(timer);
      const out = (key: 'stdout' | 'stderr') =>
        truncate(redactor.redact(Buffer.concat(chunks[key]).toString('utf-8')), MAX_OUTPUT_CHARS);
      res({ exitCode: code, signal, timedOut, stdout: out('stdout'), stderr: out('stderr') });
    });
  });
}

export interface HttpInput {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export interface HttpResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
}

/** Throws if a secret is pinned to hosts and the request goes elsewhere. */
export function assertHostAllowed(store: SecretStore, names: string[], url: URL): void {
  for (const name of names) {
    const hosts = store.meta(name)?.hosts;
    if (hosts && !hosts.includes(url.hostname.toLowerCase())) {
      throw new Error(`Secret "${name}" may only be sent to: ${hosts.join(', ')} (request goes to ${url.hostname}).`);
    }
  }
}

export async function httpWithSecrets(store: SecretStore, input: HttpInput): Promise<HttpResult> {
  const headerEntries = Object.entries(input.headers ?? {});
  const names = placeholderNames(input.url, input.body, ...headerEntries.map(([, v]) => v));
  if (names.length === 0) throw new Error('No {{secret:NAME}} placeholder found in url, headers or body.');
  const values = resolveMany(store, names);
  const redactor = new Redactor(values);

  const url = new URL(fill(input.url, values));
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '::1'].includes(url.hostname)) {
    throw new Error('Secrets are only sent over https (or to localhost).');
  }
  assertHostAllowed(store, names, url);

  try {
    const response = await fetch(url, {
      method: input.method ?? 'GET',
      headers: Object.fromEntries(headerEntries.map(([k, v]) => [k, fill(v, values)])),
      body: input.body === undefined ? undefined : fill(input.body, values),
      // Never forward secrets to wherever a redirect points.
      redirect: 'manual',
      signal: AbortSignal.timeout(input.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => { headers[k] = redactor.redact(v); });
    const body = truncate(redactor.redact(await response.text()), MAX_OUTPUT_CHARS);
    return { status: response.status, statusText: response.statusText, headers, body };
  } catch (err) {
    throw new Error(redactor.redact(err instanceof Error ? err.message : String(err)));
  }
}

function registerWrittenFile(path: string): void {
  const registry = writtenFilesPath();
  mkdirSync(dirname(registry), { recursive: true, mode: 0o700 });
  const known = existsSync(registry) ? readFileSync(registry, 'utf-8').split('\n') : [];
  if (!known.includes(path)) appendFileSync(registry, `${path}\n`, { mode: 0o600 });
}

export function writeFileWithSecrets(store: SecretStore, path: string, content: string): { path: string; secrets: string[] } {
  const names = placeholderNames(content);
  if (names.length === 0) throw new Error('No {{secret:NAME}} placeholder found in content.');
  const values = resolveMany(store, names);
  const abs = resolve(path);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, fill(content, values), { mode: 0o600 });
  registerWrittenFile(abs);
  return { path: abs, secrets: names };
}
