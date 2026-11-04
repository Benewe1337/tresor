/**
 * `.env` import: moves values out of a plaintext .env into the credential store,
 * records the mapping in .tresor.json, and optionally strips the imported lines
 * from the .env. Values are verified by reading them back before anything is removed.
 */

import { parse as parseDotenv } from 'dotenv';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { exec } from './platform/exec.js';
import { mergeProfile, type Profile } from './profile.js';
import type { SecretStore } from './store.js';

const SECRET_KEY_RE = /(KEY|TOKEN|SECRET|PASS(WORD)?|PWD|AUTH|CREDENTIAL|PRIVATE|DSN|SESSION|COOKIE|SALT|SIGNING|WEBHOOK|BEARER)/i;
const CREDS_IN_URL_RE = /^[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i;

/** Heuristic: does this .env entry look like a credential rather than config? */
export function looksSecret(key: string, value: string): boolean {
  if (!value || /^(true|false|yes|no|on|off|\d+(\.\d+)?)$/i.test(value)) return false;
  if (SECRET_KEY_RE.test(key) || CREDS_IN_URL_RE.test(value)) return true;
  // Long, mixed letters+digits, no spaces: typical opaque token.
  return value.length >= 24 && /^[A-Za-z0-9_\-.+/=:]+$/.test(value) && /\d/.test(value) && /[A-Za-z]/.test(value);
}

export function secretNameFor(key: string, prefix?: string): string {
  const base = key.toLowerCase().replace(/_/g, '-').replace(/[^a-z0-9.-]/g, '').replace(/^-+/, '');
  return (prefix ? `${prefix}-${base}` : base).slice(0, 64);
}

export interface ImportPlanItem {
  key: string;
  name: string;
  secretLike: boolean;
  selected: boolean;
  /** Why it is skipped even if selected (exists already, multi-line …). */
  skip?: string;
  multiline: boolean;
}

export interface ImportOptions {
  prefix?: string;
  all?: boolean;
  only?: string[];
  except?: string[];
  overwrite?: boolean;
}

export function planImport(store: SecretStore, envFile: string, opts: ImportOptions = {}): ImportPlanItem[] {
  const parsed = parseDotenv(readFileSync(envFile));
  return Object.entries(parsed).map(([key, value]) => {
    const name = secretNameFor(key, opts.prefix);
    const secretLike = looksSecret(key, value);
    const selected = opts.only ? opts.only.includes(key) : (opts.all || secretLike) && !(opts.except ?? []).includes(key);
    const existing = store.meta(name);
    const skip = !value ? 'empty value'
      : existing?.source ? `"${name}" is linked to ${existing.source.provider}`
      : existing && !opts.overwrite ? `"${name}" already exists (use --overwrite)`
      : undefined;
    return { key, name, secretLike, selected, skip, multiline: value.includes('\n') };
  });
}

export interface ImportResult {
  imported: Array<{ key: string; name: string }>;
  skipped: Array<{ key: string; reason: string }>;
  profile: Profile | null;
  removedFromEnvFile: string[];
  warnings: string[];
}

/** Removes `KEY=...` lines for the given single-line keys; keeps everything else verbatim. */
function stripKeys(content: string, keys: Set<string>): string {
  return content.split(/(?<=\n)/).filter(line => {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=/.exec(line);
    return !(m && keys.has(m[1]));
  }).join('');
}

async function trackedByGit(file: string): Promise<boolean> {
  const r = await exec('git', ['ls-files', '--error-unmatch', file], { cwd: dirname(file) }).catch(() => null);
  return r?.code === 0;
}

export async function runImport(
  store: SecretStore,
  envFileArg: string,
  opts: ImportOptions & { remove?: boolean } = {},
): Promise<ImportResult> {
  const envFile = resolve(envFileArg);
  if (!existsSync(envFile)) throw new Error(`File not found: ${envFile}`);
  const values = parseDotenv(readFileSync(envFile));
  const plan = planImport(store, envFile, opts);
  const result: ImportResult = { imported: [], skipped: [], profile: null, removedFromEnvFile: [], warnings: [] };

  for (const item of plan) {
    if (!item.selected) continue;
    if (item.skip) { result.skipped.push({ key: item.key, reason: item.skip }); continue; }
    store.set(item.name, values[item.key], { description: `imported from ${envFile} (${item.key})` });
    if ((await store.resolve(item.name)) !== values[item.key]) {
      result.skipped.push({ key: item.key, reason: 'read-back mismatch, kept in .env' });
      continue;
    }
    result.imported.push({ key: item.key, name: item.name });
  }

  if (result.imported.length > 0) {
    result.profile = mergeProfile(dirname(envFile), Object.fromEntries(result.imported.map(i => [i.key, i.name])));
  }

  if (opts.remove && result.imported.length > 0) {
    const removable = new Set(result.imported.map(i => i.key).filter(k => !values[k].includes('\n')));
    const multi = result.imported.map(i => i.key).filter(k => !removable.has(k));
    if (multi.length) result.warnings.push(`multi-line values left in ${envFile}: ${multi.join(', ')} – remove them by hand`);
    writeFileSync(envFile, stripKeys(readFileSync(envFile, 'utf-8'), removable));
    result.removedFromEnvFile = [...removable];
  }

  if (await trackedByGit(envFile)) {
    result.warnings.push(`${envFile} is tracked by git – these values are in your history. Rotate them and add the file to .gitignore.`);
  }
  return result;
}
