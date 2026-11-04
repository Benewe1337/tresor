/**
 * Dynamic (short-lived) credentials: instead of a stored long-lived token, a
 * secret name points to a generator that mints a fresh credential when used and
 * caches it until shortly before it expires.
 *
 *   aws-sso     aws configure export-credentials  → AWS_ACCESS_KEY_ID, … (bundle)
 *   gcloud      gcloud auth print-access-token    → access token (~1 h)
 *   azure       az account get-access-token       → access token (5–60 min)
 *   github-app  GitHub App installation token     → token (1 h), minted via JWT
 *   oauth       OAuth 2.0 refresh_token grant     → access token, rotated refresh token
 *   command     any CLI printing a value or JSON  → value or bundle
 *
 * Nothing here ever starts an interactive login; expired logins surface as errors
 * with the command the user has to run.
 */

import { createSign } from 'crypto';
import { existsSync, mkdirSync, rmSync, statSync } from 'fs';
import { join } from 'path';
import { tresorHome } from './paths.js';
import { exec } from './platform/exec.js';
import { pickJson } from './providers/common.js';
import type { ProviderContext } from './providers/types.js';

export type DynamicType = 'aws-sso' | 'gcloud' | 'azure' | 'github-app' | 'oauth' | 'command';
export const DYNAMIC_TYPES: readonly DynamicType[] = ['aws-sso', 'gcloud', 'azure', 'github-app', 'oauth', 'command'];

export interface DynamicConfig {
  type: DynamicType;
  /** Non-secret options; secret inputs live in the credential store under __internal.*. */
  options: Record<string, unknown>;
}

export interface Minted {
  /** Single-value generators use the key "value"; bundles use env var names. */
  values: Record<string, string>;
  /** epoch ms */
  expiresAt?: number;
}

export interface GenContext extends ProviderContext {
  name: string;
  resolveSecret(name: string): Promise<string>;
}

const MINT_TIMEOUT_MS = 30_000;
export const DEFAULT_GCLOUD_TTL_S = 55 * 60;

export class DynamicError extends Error {}

const str = (o: Record<string, unknown>, k: string): string | undefined => (typeof o[k] === 'string' && o[k] ? (o[k] as string) : undefined);

function need(o: Record<string, unknown>, k: string, type: string): string {
  const v = str(o, k);
  if (!v) throw new DynamicError(`${type}: option "${k}" is required`);
  return v;
}

/** Accepts ISO/RFC3339 strings, epoch seconds or epoch ms. */
export function parseExpiry(v: unknown): number | undefined {
  if (typeof v === 'number' || (typeof v === 'string' && /^\d+$/.test(v))) {
    const n = Number(v);
    return n < 1e12 ? n * 1000 : n;
  }
  if (typeof v === 'string') {
    const t = Date.parse(v);
    return Number.isNaN(t) ? undefined : t;
  }
  return undefined;
}

async function runGenerator(label: string, bin: string, args: string[], ctx: GenContext, hint: string, env: NodeJS.ProcessEnv = ctx.env): Promise<string> {
  const r = await exec(bin, args, { env, timeoutMs: MINT_TIMEOUT_MS }).catch(e => {
    throw new DynamicError(`${label}: cannot run ${bin} (${e instanceof Error ? e.message : e})`);
  });
  if (r.timedOut) throw new DynamicError(`${label}: ${bin} timed out (waiting for a login?). ${hint}`);
  if (r.code !== 0) {
    const first = (r.stderr || r.stdout).trim().split('\n')[0] ?? '';
    throw new DynamicError(`${label}: ${first || `exit code ${r.code}`}. ${hint}`);
  }
  return r.stdout.replace(/\r?\n$/, '');
}

// ─── AWS IAM Identity Center ─────────────────────────────────────────────────

async function mintAwsSso(o: Record<string, unknown>, ctx: GenContext): Promise<Minted> {
  const profile = need(o, 'profile', 'aws-sso');
  const out = await runGenerator('aws-sso', 'aws', ['configure', 'export-credentials', '--profile', profile, '--format', 'process'],
    ctx, `Run: aws sso login --profile ${profile}`, { ...ctx.env, AWS_PAGER: '' });
  const j = JSON.parse(out) as { AccessKeyId?: string; SecretAccessKey?: string; SessionToken?: string; Expiration?: string };
  if (!j.AccessKeyId || !j.SecretAccessKey) throw new DynamicError('aws-sso: unexpected export-credentials output');
  const values: Record<string, string> = { AWS_ACCESS_KEY_ID: j.AccessKeyId, AWS_SECRET_ACCESS_KEY: j.SecretAccessKey };
  if (j.SessionToken) values.AWS_SESSION_TOKEN = j.SessionToken;
  if (j.Expiration) values.AWS_CREDENTIAL_EXPIRATION = j.Expiration;
  return { values, expiresAt: parseExpiry(j.Expiration) };
}

// ─── Google Cloud ────────────────────────────────────────────────────────────

async function mintGcloud(o: Record<string, unknown>, ctx: GenContext): Promise<Minted> {
  const account = str(o, 'account');
  const sa = str(o, 'impersonate');
  const args = ['auth', 'print-access-token', ...(account ? [account] : []), ...(sa ? [`--impersonate-service-account=${sa}`] : []), '--quiet'];
  const token = await runGenerator('gcloud', 'gcloud', args, ctx, 'Run: gcloud auth login', { ...ctx.env, CLOUDSDK_CORE_DISABLE_PROMPTS: '1' });
  // gcloud prints no expiry; tokens live ~1 h.
  return { values: { value: token.trim() }, expiresAt: Date.now() + DEFAULT_GCLOUD_TTL_S * 1000 };
}

// ─── Azure ───────────────────────────────────────────────────────────────────

async function mintAzure(o: Record<string, unknown>, ctx: GenContext): Promise<Minted> {
  const args = ['account', 'get-access-token',
    ...(str(o, 'resource') ? ['--resource', str(o, 'resource')!] : []),
    ...(str(o, 'scope') ? ['--scope', str(o, 'scope')!] : []),
    ...(str(o, 'tenant') ? ['--tenant', str(o, 'tenant')!] : []),
    '-o', 'json', '--only-show-errors'];
  const j = JSON.parse(await runGenerator('azure', 'az', args, ctx, 'Run: az login')) as Record<string, unknown>;
  const token = typeof j.accessToken === 'string' ? j.accessToken : '';
  if (!token) throw new DynamicError('azure: no accessToken in az output');
  return { values: { value: token }, expiresAt: parseExpiry(j.expires_on) ?? parseExpiry(j.expiresOn) };
}

// ─── GitHub App ──────────────────────────────────────────────────────────────

const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64url');

export function githubAppJwt(issuer: string, privateKeyPem: string, now = Math.floor(Date.now() / 1000)): string {
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 9 * 60, iss: issuer }));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${signer.sign(privateKeyPem).toString('base64url')}`;
}

export const githubKeyInternal = (name: string) => `github-app.${name}.key`;

async function mintGithubApp(o: Record<string, unknown>, ctx: GenContext): Promise<Minted> {
  const appId = need(o, 'appId', 'github-app');
  const installationId = need(o, 'installationId', 'github-app');
  const apiUrl = (str(o, 'apiUrl') ?? 'https://api.github.com').replace(/\/+$/, '');
  const keySecret = str(o, 'privateKeySecret');
  const pem = keySecret ? await ctx.resolveSecret(keySecret) : ctx.internal.get(githubKeyInternal(ctx.name));
  if (!pem) throw new DynamicError(`github-app: private key missing. Re-run: tresor dynamic ${ctx.name} github-app … --private-key-file <file.pem>`);
  const body: Record<string, unknown> = {};
  if (Array.isArray(o.repositories) && o.repositories.length) body.repositories = o.repositories;
  if (o.permissions && typeof o.permissions === 'object') body.permissions = o.permissions;
  const res = await fetch(`${apiUrl}/app/installations/${encodeURIComponent(installationId)}/access_tokens`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${githubAppJwt(appId, pem)}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'tresor',
      ...(Object.keys(body).length ? { 'Content-Type': 'application/json' } : {}),
    },
    body: Object.keys(body).length ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(MINT_TIMEOUT_MS),
  });
  const j = (await res.json().catch(() => ({}))) as { token?: string; expires_at?: string; message?: string };
  if (!res.ok || !j.token) {
    throw new DynamicError(`github-app: HTTP ${res.status} ${j.message ?? ''}`.trim() + (res.status === 401 ? ' (wrong key/app id or clock skew)' : res.status === 404 ? ' (installation not found)' : ''));
  }
  return { values: { value: j.token }, expiresAt: parseExpiry(j.expires_at) };
}

// ─── OAuth 2.0 refresh_token grant ───────────────────────────────────────────

export const oauthRefreshInternal = (name: string) => `oauth.${name}.refresh`;
export const oauthClientSecretInternal = (name: string) => `oauth.${name}.client-secret`;

const LOCK_STALE_MS = 60_000;

/** Cross-process lock so two refreshes never race with the same (rotating) refresh token. */
async function withFileLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const dir = join(tresorHome(), 'locks');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = join(dir, key.replace(/[^A-Za-z0-9_.-]/g, '_'));
  for (let i = 0; ; i++) {
    try { mkdirSync(lock); break; } catch {
      if (existsSync(lock) && Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) rmSync(lock, { recursive: true, force: true });
      if (i > 300) throw new DynamicError(`timed out waiting for lock ${key}`);
      await new Promise(r => setTimeout(r, 100));
    }
  }
  try { return await fn(); } finally { rmSync(lock, { recursive: true, force: true }); }
}

async function mintOauth(o: Record<string, unknown>, ctx: GenContext): Promise<Minted> {
  const tokenUrl = need(o, 'tokenUrl', 'oauth');
  const clientId = need(o, 'clientId', 'oauth');
  const auth = (str(o, 'authMethod') ?? 'basic') as 'basic' | 'post' | 'none';
  return withFileLock(`oauth-${ctx.name}`, async () => {
    const refresh = ctx.internal.get(oauthRefreshInternal(ctx.name));
    if (!refresh) throw new DynamicError(`oauth: no refresh token stored. Run: tresor dynamic ${ctx.name} oauth …`);
    const secret = auth === 'none' ? null : ctx.internal.get(oauthClientSecretInternal(ctx.name));
    if (auth !== 'none' && !secret) throw new DynamicError(`oauth: client secret missing. Run: tresor dynamic ${ctx.name} oauth …`);
    const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refresh });
    if (str(o, 'scope')) form.set('scope', str(o, 'scope')!);
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
    if (auth === 'basic') {
      headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret!)}`).toString('base64')}`;
    } else {
      form.set('client_id', clientId);
      if (auth === 'post') form.set('client_secret', secret!);
    }
    const res = await fetch(tokenUrl, { method: 'POST', headers, body: form, signal: AbortSignal.timeout(MINT_TIMEOUT_MS) });
    const j = (await res.json().catch(() => ({}))) as { access_token?: string; refresh_token?: string; expires_in?: number; error?: string; error_description?: string };
    if (!res.ok || !j.access_token) {
      const hint = j.error === 'invalid_grant' ? ` The refresh token is expired or revoked – log in again and re-run: tresor dynamic ${ctx.name} oauth …` : '';
      throw new DynamicError(`oauth: HTTP ${res.status} ${j.error ?? ''} ${j.error_description ?? ''}`.trim() + hint);
    }
    // Rotation: persist the new refresh token before handing out the access token.
    if (j.refresh_token && j.refresh_token !== refresh) ctx.internal.set(oauthRefreshInternal(ctx.name), j.refresh_token);
    return { values: { value: j.access_token }, expiresAt: typeof j.expires_in === 'number' ? Date.now() + j.expires_in * 1000 : undefined };
  });
}

// ─── Generic command ─────────────────────────────────────────────────────────

async function mintCommand(o: Record<string, unknown>, ctx: GenContext): Promise<Minted> {
  const argv = o.argv;
  if (!Array.isArray(argv) || argv.length === 0 || argv.some(a => typeof a !== 'string')) throw new DynamicError('command: "argv" must be a non-empty string array');
  const [bin, ...args] = argv as string[];
  const out = await runGenerator('command', bin, args, ctx, str(o, 'hint') ?? '');
  const outputs = o.outputs && typeof o.outputs === 'object' ? (o.outputs as Record<string, string>) : undefined;
  const valuePath = str(o, 'jsonPath');
  if (!outputs && !valuePath) {
    const ttl = typeof o.ttlSeconds === 'number' ? o.ttlSeconds : undefined;
    return { values: { value: out }, expiresAt: ttl ? Date.now() + ttl * 1000 : undefined };
  }
  let json: unknown;
  try { json = JSON.parse(out); } catch { throw new DynamicError('command: output is not JSON'); }
  const pick = (path: string) => {
    const v = pickJson(json, path);
    if (v === undefined || v === null || v === '') throw new DynamicError(`command: nothing at JSON path "${path}"`);
    return typeof v === 'string' ? v : String(v);
  };
  const values = outputs ? Object.fromEntries(Object.entries(outputs).map(([env, p]) => [env, pick(p)])) : { value: pick(valuePath!) };
  let expiresAt: number | undefined;
  if (str(o, 'expiresPath')) expiresAt = parseExpiry(pickJson(json, str(o, 'expiresPath')!));
  else if (str(o, 'ttlPath')) { const t = Number(pickJson(json, str(o, 'ttlPath')!)); if (t > 0) expiresAt = Date.now() + t * 1000; }
  else if (typeof o.ttlSeconds === 'number') expiresAt = Date.now() + o.ttlSeconds * 1000;
  return { values, expiresAt };
}

// ─── Registry ────────────────────────────────────────────────────────────────

const MINTERS: Record<DynamicType, (o: Record<string, unknown>, ctx: GenContext) => Promise<Minted>> = {
  'aws-sso': mintAwsSso,
  gcloud: mintGcloud,
  azure: mintAzure,
  'github-app': mintGithubApp,
  oauth: mintOauth,
  command: mintCommand,
};

/** Bundles fill several env vars at once; everything else yields one value. */
export function isBundle(cfg: DynamicConfig): boolean {
  return cfg.type === 'aws-sso' || (cfg.type === 'command' && Boolean(cfg.options.outputs));
}

export function validateDynamic(cfg: DynamicConfig): void {
  if (!DYNAMIC_TYPES.includes(cfg.type)) throw new DynamicError(`Unknown dynamic type "${cfg.type}". Available: ${DYNAMIC_TYPES.join(', ')}`);
  const o = cfg.options;
  if (cfg.type === 'aws-sso') need(o, 'profile', cfg.type);
  if (cfg.type === 'github-app') { need(o, 'appId', cfg.type); need(o, 'installationId', cfg.type); }
  if (cfg.type === 'oauth') {
    need(o, 'tokenUrl', cfg.type);
    need(o, 'clientId', cfg.type);
    if (!/^https:\/\//.test(str(o, 'tokenUrl')!) && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(str(o, 'tokenUrl')!)) throw new DynamicError('oauth: tokenUrl must be https');
    if (!['basic', 'post', 'none', undefined].includes(str(o, 'authMethod'))) throw new DynamicError('oauth: authMethod must be basic, post or none');
  }
  if (cfg.type === 'command' && (!Array.isArray(o.argv) || o.argv.length === 0)) throw new DynamicError('command: "argv" is required');
}

/** Internal credential keys owned by a dynamic secret (removed with it). */
export function internalKeysFor(name: string, cfg: DynamicConfig): string[] {
  if (cfg.type === 'github-app') return [githubKeyInternal(name)];
  if (cfg.type === 'oauth') return [oauthRefreshInternal(name), oauthClientSecretInternal(name)];
  return [];
}

export function mint(cfg: DynamicConfig, ctx: GenContext): Promise<Minted> {
  return MINTERS[cfg.type](cfg.options, ctx);
}

/** When a cached credential should be replaced: before expiry by max(60 s, 10 % of its lifetime). */
export function staleAt(m: Minted, now = Date.now()): number {
  if (!m.expiresAt) return now; // unknown lifetime → do not cache
  return m.expiresAt - Math.max(60_000, (m.expiresAt - now) * 0.1);
}
