/**
 * Project profiles: a `.tresor.json` in a repo maps environment variables to
 * secret names, e.g. { "env": { "OPENAI_API_KEY": "openai" } }. It contains no
 * values and is meant to be committed.
 *
 * Because a cloned repo could ship a profile that asks for *your* secrets, a
 * profile is only used after the user approved that exact content (like
 * `direnv allow`); any change needs approval again.
 */

import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { dirname, join, parse, resolve } from 'path';
import { trustedProfilesPath } from './paths.js';

export const PROFILE_FILENAME = '.tresor.json';
const ENV_VAR_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export interface Profile {
  path: string;
  env: Record<string, string>;
  /** Multi-value dynamic secrets (e.g. aws-sso) injected with their own variable names. */
  bundles: string[];
  hash: string;
}

function parseProfile(path: string, raw: string): Profile {
  let json: unknown;
  try { json = JSON.parse(raw); } catch { throw new Error(`${path}: invalid JSON`); }
  const { env = {}, bundles = [] } = (json ?? {}) as { env?: unknown; bundles?: unknown };
  if (typeof env !== 'object' || env === null || Array.isArray(env)) throw new Error(`${path}: expected {"env": {"VAR": "secret-name"}, "bundles": ["name"]}`);
  for (const [k, v] of Object.entries(env)) {
    if (!ENV_VAR_RE.test(k) || typeof v !== 'string') throw new Error(`${path}: bad mapping "${k}"`);
  }
  if (!Array.isArray(bundles) || bundles.some(b => typeof b !== 'string')) throw new Error(`${path}: "bundles" must be a list of secret names`);
  return { path, env: env as Record<string, string>, bundles: bundles as string[], hash: createHash('sha256').update(raw).digest('hex') };
}

/** Nearest .tresor.json from `cwd` upwards, or null. */
export function findProfile(cwd = process.cwd()): Profile | null {
  let dir = resolve(cwd);
  const { root } = parse(dir);
  for (;;) {
    const candidate = join(dir, PROFILE_FILENAME);
    if (existsSync(candidate)) return parseProfile(candidate, readFileSync(candidate, 'utf-8'));
    if (dir === root) return null;
    dir = dirname(dir);
  }
}

/** Adds/overrides mappings in `<dir>/.tresor.json`, creating it if needed. */
export function mergeProfile(dir: string, mappings: Record<string, string>, remove: string[] = [], addBundles: string[] = []): Profile {
  const path = join(resolve(dir), PROFILE_FILENAME);
  const current = existsSync(path) ? parseProfile(path, readFileSync(path, 'utf-8')) : { env: {}, bundles: [] as string[] };
  const next = Object.fromEntries(
    Object.entries({ ...current.env, ...mappings }).filter(([k]) => !remove.includes(k)).sort(([a], [b]) => a.localeCompare(b)),
  );
  for (const k of Object.keys(mappings)) if (!ENV_VAR_RE.test(k)) throw new Error(`Invalid environment variable name "${k}"`);
  const bundles = [...new Set([...current.bundles, ...addBundles])].filter(b => !remove.includes(b));
  const raw = JSON.stringify(bundles.length ? { env: next, bundles } : { env: next }, null, 2) + '\n';
  writeFileSync(path, raw);
  return parseProfile(path, raw);
}

function readTrusted(): Record<string, string> {
  const file = trustedProfilesPath();
  if (!existsSync(file)) return {};
  try { return JSON.parse(readFileSync(file, 'utf-8')) as Record<string, string>; } catch { return {}; }
}

export function isTrusted(profile: Profile): boolean {
  return readTrusted()[profile.path] === profile.hash;
}

export function trustProfile(profile: Profile): void {
  const file = trustedProfilesPath();
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(`${file}.tmp`, JSON.stringify({ ...readTrusted(), [profile.path]: profile.hash }, null, 2) + '\n', { mode: 0o600 });
  renameSync(`${file}.tmp`, file);
}

export function describeProfile(profile: Profile): string {
  return [
    ...Object.entries(profile.env).map(([k, v]) => `${k} ← ${v}`),
    ...profile.bundles.map(b => `(bundle) ${b}`),
  ].join('\n');
}
