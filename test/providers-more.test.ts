import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { splitKeyVersion } from '../src/providers/cloud.js';
import { MemoryBackend, SecretStore } from '../src/store.js';
import { Stubs } from './stubs.js';

const V = 'fake-cloud-secret-value-42';
let stubs: Stubs;
let store: SecretStore;

beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-more-'));
  stubs = new Stubs();
  store = new SecretStore(new MemoryBackend(), { providersConfig: {}, env: stubs.env() });
});

async function linkAndResolve(provider: string, ref: string): Promise<string> {
  store.link('x', provider, ref);
  try { return await store.resolve('x'); } finally { store.remove('x'); }
}

describe('reference parsing', () => {
  it('splits id, version and key', () => {
    expect(splitKeyVersion('prod/db@AWSPREVIOUS#password')).toEqual({ id: 'prod/db', version: 'AWSPREVIOUS', key: 'password' });
    expect(splitKeyVersion('arn:aws:secretsmanager:eu-central-1:1:secret:x')).toEqual({ id: 'arn:aws:secretsmanager:eu-central-1:1:secret:x', version: undefined, key: undefined });
  });
});

describe('password managers', () => {
  it('Proton Pass reads pass:// references', async () => {
    stubs.add('pass-cli', [{ match: ['item', 'view', 'pass://Work/GitHub/password'], stdout: `${V}\n` }]);
    expect(await linkAndResolve('protonpass', 'pass://Work/GitHub/password')).toBe(V);
    expect(() => store.link('y', 'protonpass', 'Work/GitHub')).toThrow(/pass:\/\//);
  });

  it('Dashlane reads dl:// references and parses dcli status text', async () => {
    stubs.add('dcli', [
      { match: ['read', 'dl://abcd/password'], stdout: `${V}\n` },
      { match: ['status'], stdout: 'Logged in: Yes\nLocked: Yes\n' },
    ]);
    expect(await linkAndResolve('dashlane', 'dl://abcd/password')).toBe(V);
    const st = (await store.providerStatuses()).find(p => p.id === 'dashlane')!;
    expect(st).toMatchObject({ installed: true, ready: false });
  });

  it('Keeper maps fields to clipboard-copy flags and treats empty output as missing', async () => {
    stubs.add('keeper', [
      { match: ['--batch-mode', 'clipboard-copy', '--output', 'stdout', 'UID1'], stdout: `${V}\n` },
      { match: ['--batch-mode', 'clipboard-copy', '--output', 'stdout', '--totp', 'UID1'], stdout: '123456\n' },
      { match: ['--batch-mode', 'clipboard-copy', '--output', 'stdout', '--field', 'API Key', 'UID1'], stdout: '' },
    ]);
    expect(await linkAndResolve('keeper', 'UID1')).toBe(V);
    expect(await linkAndResolve('keeper', 'UID1#totp')).toBe('123456');
    await expect(linkAndResolve('keeper', 'UID1#API Key')).rejects.toThrow(/empty or missing/);
  });
});

describe('cloud stores', () => {
  it('AWS Secrets Manager: text output, JSON key, stage, no pager', async () => {
    stubs.add('aws', [
      { match: ['secretsmanager', 'get-secret-value', '--secret-id', 'prod/db', '--query', 'SecretString', '--output', 'text', '--no-cli-pager', '--version-stage', 'AWSPREVIOUS'], stdout: '{"password":"old-pw-123456"}\n' },
      { match: ['secretsmanager', 'get-secret-value', '--secret-id', 'prod/api'], stdout: `${V}\n` },
    ]);
    expect(await linkAndResolve('aws-sm', 'prod/db@AWSPREVIOUS#password')).toBe('old-pw-123456');
    expect(await linkAndResolve('aws-sm', 'prod/api')).toBe(V);
    await expect(linkAndResolve('aws-sm', 'prod/api#nokey')).rejects.toThrow(/not JSON/);
  });

  it('Azure Key Vault: vault/name/version and full ids', async () => {
    stubs.add('az', [
      { match: ['keyvault', 'secret', 'show', '--vault-name', 'kv1', '--name', 'stripe', '--query', 'value'], stdout: `${V}\n` },
      { match: ['keyvault', 'secret', 'show', '--id', 'https://kv1.vault.azure.net/secrets/stripe/abc'], stdout: `${V}\n` },
    ]);
    expect(await linkAndResolve('azure-kv', 'kv1/stripe')).toBe(V);
    expect(await linkAndResolve('azure-kv', 'https://kv1.vault.azure.net/secrets/stripe/abc')).toBe(V);
    expect(() => store.link('y', 'azure-kv', 'just-a-name')).toThrow(/Azure Key Vault reference/);
  });

  it('Google Secret Manager: project, version default latest, prompts disabled', async () => {
    stubs.add('gcloud', [
      { match: ['secrets', 'versions', 'access', 'latest', '--secret', 'api', '--project', 'proj1', '--quiet'], stdout: V },
      { match: ['secrets', 'versions', 'access', '3', '--secret', 'cfg', '--quiet'], stdout: '{"k":"v-123456789"}' },
    ]);
    expect(await linkAndResolve('gcp-sm', 'proj1/api')).toBe(V);
    expect(await linkAndResolve('gcp-sm', 'cfg@3#k')).toBe('v-123456789');
  });

  it('Doppler: scoped and unscoped names', async () => {
    stubs.add('doppler', [
      { match: ['secrets', 'get', 'STRIPE', '--plain', '--project', 'shop', '--config', 'prd'], stdout: `${V}\n` },
      { match: ['secrets', 'get', 'STRIPE', '--plain', '--no-check-version'], stdout: `${V}\n` },
    ]);
    expect(await linkAndResolve('doppler', 'shop/prd/STRIPE')).toBe(V);
    expect(await linkAndResolve('doppler', 'STRIPE')).toBe(V);
    expect(() => store.link('y', 'doppler', 'shop/STRIPE')).toThrow(/Doppler reference/);
  });

  it('Infisical: sm namespace, legacy fallback and "*not found*"', async () => {
    stubs.add('infisical', [
      { match: ['sm', 'secrets', 'get', 'KEY', '--plain', '--silent', '--env', 'prod', '--path', '/api', '--projectId', 'p1'], stdout: `${V}\n` },
      { match: ['sm', 'secrets', 'get', 'OLD'], stderr: 'Error: unknown command "sm" for "infisical"', code: 1 },
      { match: ['secrets', 'get', 'OLD', '--plain', '--silent', '--env', 'dev', '--path', '/', '--projectId', 'p1'], stdout: `${V}\n` },
      { match: ['sm', 'secrets', 'get', 'GONE'], stdout: '*not found*\n' },
    ]);
    expect(await linkAndResolve('infisical', 'p1/prod/api/KEY')).toBe(V);
    expect(await linkAndResolve('infisical', 'p1/dev/OLD')).toBe(V);
    await expect(linkAndResolve('infisical', 'p1/dev/GONE')).rejects.toThrow(/not found/);
  });

  it('Vault and OpenBao: mount, field, version', async () => {
    stubs.add('vault', [{ match: ['kv', 'get', '-mount=secret', '-field=api_key', '-version=2', 'app/stripe'], stdout: V }]);
    stubs.add('bao', [{ match: ['kv', 'get', '-mount=kv', '-field=pw', 'db'], stdout: V }]);
    expect(await linkAndResolve('vault', 'secret/app/stripe@2#api_key')).toBe(V);
    expect(await linkAndResolve('openbao', 'kv/db#pw')).toBe(V);
    expect(() => store.link('y', 'vault', 'secret/app/stripe')).toThrow(/Vault reference/);
  });

  it('lists all built-in providers', async () => {
    const ids = (await store.providerStatuses()).map(p => p.id);
    expect(ids).toEqual(['1password', 'bitwarden', 'bws', 'keepassxc', 'protonpass', 'dashlane', 'keeper', 'pass', 'gopass', 'lastpass',
      'aws-sm', 'azure-kv', 'gcp-sm', 'doppler', 'infisical', 'vault', 'openbao']);
  });
});
