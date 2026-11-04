/**
 * Cloud secret stores and team secret managers: AWS Secrets Manager, Azure Key
 * Vault, Google Secret Manager, Doppler, Infisical, HashiCorp Vault / OpenBao.
 * Command lines follow the vendors' docs (researched 2026-11).
 */

import { exec, onPath } from '../platform/exec.js';
import { notInstalled, requireNonEmpty, runCli, splitField } from './common.js';
import { ProviderError, type Provider, type ProviderContext } from './types.js';

const STATUS_TIMEOUT = 20_000;

async function statusByExit(bin: string, args: string[], ctx: ProviderContext, failDetail: string, env: NodeJS.ProcessEnv = ctx.env) {
  if (!onPath(bin, ctx.env)) return notInstalled(bin);
  const r = await exec(bin, args, { env, timeoutMs: STATUS_TIMEOUT }).catch(() => null);
  return r?.code === 0 ? { installed: true, ready: true, detail: 'authenticated' } : { installed: true, ready: false, detail: failDetail };
}

/** Picks a top-level key from a JSON string secret (AWS/GCP style). */
function pickJsonKey(label: string, raw: string, key: string): string {
  let json: unknown;
  try { json = JSON.parse(raw); } catch { throw new ProviderError(`${label}: secret is not JSON, cannot pick "#${key}".`); }
  const v = (json as Record<string, unknown>)?.[key];
  if (v === undefined) throw new ProviderError(`${label}: JSON secret has no key "${key}".`);
  return typeof v === 'string' ? v : JSON.stringify(v);
}

/** Uniform reference syntax for cloud stores: `id[@version][#key]`. */
export function splitKeyVersion(ref: string): { id: string; key?: string; version?: string } {
  const { path: base, field: key } = splitField(ref);
  const at = base.lastIndexOf('@');
  const version = at > 0 && !base.slice(at).includes('/') ? base.slice(at + 1) : undefined;
  return { id: version ? base.slice(0, at) : base, key, version };
}

const AWS_ENV = (ctx: ProviderContext) => ({ ...ctx.env, AWS_PAGER: '' });

export const awsSecretsManager: Provider = {
  id: 'aws-sm',
  label: 'AWS Secrets Manager',
  refHelp: '<secret name or ARN>[@stage][#jsonKey]   (stage default AWSCURRENT; region/profile from AWS_REGION/AWS_PROFILE)',
  validateRef(ref) {
    if (!splitKeyVersion(ref).id.trim()) throw new ProviderError(`AWS Secrets Manager reference: ${this.refHelp}`);
  },
  async resolve(ref, ctx) {
    this.validateRef(ref);
    const { id, key, version } = splitKeyVersion(ref);
    const args = ['secretsmanager', 'get-secret-value', '--secret-id', id, '--query', 'SecretString', '--output', 'text', '--no-cli-pager',
      ...(version ? ['--version-stage', version] : [])];
    const raw = await runCli(this.label, 'aws', args, { env: AWS_ENV(ctx) });
    return requireNonEmpty(this.label, ref, key ? pickJsonKey(this.label, raw, key) : raw);
  },
  status: ctx => statusByExit('aws', ['sts', 'get-caller-identity', '--no-cli-pager'], ctx, 'no AWS credentials – aws sso login / aws configure', AWS_ENV(ctx)),
};

export const azureKeyVault: Provider = {
  id: 'azure-kv',
  label: 'Azure Key Vault',
  refHelp: '<vault>/<secret>[/<version>]  or the full https://<vault>.vault.azure.net/secrets/… id',
  validateRef(ref) {
    if (!/^https:\/\/[^/]+\.vault\.azure\.net\/secrets\/.+/.test(ref) && !/^[^/]+\/[^/]+(\/[^/]+)?$/.test(ref)) {
      throw new ProviderError(`Azure Key Vault reference: ${this.refHelp}`);
    }
  },
  async resolve(ref, ctx) {
    this.validateRef(ref);
    let target: string[];
    if (ref.startsWith('https://')) {
      target = ['--id', ref];
    } else {
      const [vault, name, version] = ref.split('/');
      target = ['--vault-name', vault, '--name', name, ...(version ? ['--version', version] : [])];
    }
    const args = ['keyvault', 'secret', 'show', ...target, '--query', 'value', '-o', 'tsv', '--only-show-errors'];
    return requireNonEmpty(this.label, ref, await runCli(this.label, 'az', args, { env: ctx.env }));
  },
  status: ctx => statusByExit('az', ['account', 'show', '-o', 'none'], ctx, 'not logged in – az login'),
};

const GCLOUD_ENV = (ctx: ProviderContext) => ({ ...ctx.env, CLOUDSDK_CORE_DISABLE_PROMPTS: '1' });

export const gcpSecretManager: Provider = {
  id: 'gcp-sm',
  label: 'Google Secret Manager',
  refHelp: '[<project>/]<secret>[@<version>][#jsonKey]   (version default latest)',
  validateRef(ref) {
    if (!splitKeyVersion(ref).id.trim()) throw new ProviderError(`Google Secret Manager reference: ${this.refHelp}`);
  },
  async resolve(ref, ctx) {
    this.validateRef(ref);
    const { id, key, version = 'latest' } = splitKeyVersion(ref);
    const segs = id.split('/');
    const [project, secret] = segs.length > 1 ? [segs[0], segs.slice(1).join('/')] : [undefined, segs[0]];
    const args = ['secrets', 'versions', 'access', version, '--secret', secret, ...(project ? ['--project', project] : []), '--quiet'];
    const raw = await runCli(this.label, 'gcloud', args, { env: GCLOUD_ENV(ctx) });
    return requireNonEmpty(this.label, ref, key ? pickJsonKey(this.label, raw, key) : raw);
  },
  status: ctx => statusByExit('gcloud', ['auth', 'print-access-token', '--quiet'], ctx, 'not logged in – gcloud auth login', GCLOUD_ENV(ctx)),
};

export const doppler: Provider = {
  id: 'doppler',
  label: 'Doppler',
  refHelp: '[<project>/<config>/]<NAME>   (without project/config: DOPPLER_TOKEN scope or `doppler setup` of the cwd)',
  validateRef(ref) {
    const parts = ref.split('/');
    if (!(parts.length === 1 || parts.length === 3) || parts.some(p => !p)) throw new ProviderError(`Doppler reference: ${this.refHelp}`);
  },
  async resolve(ref, ctx) {
    this.validateRef(ref);
    const parts = ref.split('/');
    const name = parts[parts.length - 1];
    const scope = parts.length === 3 ? ['--project', parts[0], '--config', parts[1]] : [];
    const args = ['secrets', 'get', name, '--plain', ...scope, '--no-check-version', '--silent'];
    return requireNonEmpty(this.label, ref, await runCli(this.label, 'doppler', args, { env: ctx.env }));
  },
  status: ctx => statusByExit('doppler', ['me', '--no-check-version'], ctx, 'not logged in – doppler login or DOPPLER_TOKEN'),
};

export const infisical: Provider = {
  id: 'infisical',
  label: 'Infisical',
  refHelp: '<projectId>/<env>/[<folder>/…]<NAME>   (e.g. 6f1…/prod/api/STRIPE_KEY)',
  validateRef(ref) {
    if (ref.split('/').filter(Boolean).length < 3) throw new ProviderError(`Infisical reference: ${this.refHelp}`);
  },
  async resolve(ref, ctx) {
    this.validateRef(ref);
    const parts = ref.split('/').filter(Boolean);
    const [projectId, envName] = parts;
    const name = parts[parts.length - 1];
    const folder = `/${parts.slice(2, -1).join('/')}`;
    const tail = [name, '--plain', '--silent', '--env', envName, '--path', folder, '--projectId', projectId];
    let out: string;
    try {
      out = await runCli(this.label, 'infisical', ['sm', 'secrets', 'get', ...tail], { env: ctx.env });
    } catch (e) {
      // CLI versions before the `sm` namespace.
      if (!/unknown command|unknown flag/i.test(e instanceof Error ? e.message : '')) throw e;
      out = await runCli(this.label, 'infisical', ['secrets', 'get', ...tail], { env: ctx.env });
    }
    if (out.trim() === '*not found*') throw new ProviderError(`Infisical: secret "${name}" not found in ${envName}${folder}.`);
    return requireNonEmpty(this.label, ref, out);
  },
  status: ctx => statusByExit('infisical', ['login', 'status'], ctx, 'not logged in – infisical login or INFISICAL_TOKEN'),
};

function vaultLike(id: string, label: string, bin: string): Provider {
  return {
    id,
    label,
    refHelp: '<mount>/<path>[@<version>]#<field>   (e.g. secret/app/stripe#api_key)',
    validateRef(ref) {
      const { id: p, key } = splitKeyVersion(ref);
      if (!key || p.split('/').filter(Boolean).length < 2) throw new ProviderError(`${label} reference: ${this.refHelp}`);
    },
    async resolve(ref, ctx) {
      this.validateRef(ref);
      const { id: p, key, version } = splitKeyVersion(ref);
      const [mount, ...rest] = p.split('/').filter(Boolean);
      const args = ['kv', 'get', `-mount=${mount}`, `-field=${key}`, ...(version ? [`-version=${version}`] : []), rest.join('/')];
      return requireNonEmpty(label, ref, await runCli(label, bin, args, { env: ctx.env }));
    },
    status: ctx => statusByExit(bin, ['token', 'lookup'], ctx, `no valid token – ${bin} login or ${bin === 'bao' ? 'BAO_TOKEN' : 'VAULT_TOKEN'}`),
  };
}

export const hashicorpVault = vaultLike('vault', 'HashiCorp Vault', 'vault');
export const openBao = vaultLike('openbao', 'OpenBao', 'bao');
