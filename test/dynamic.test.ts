import { createVerify, generateKeyPairSync } from 'crypto';
import { createServer, type IncomingMessage, type Server } from 'http';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { githubAppJwt, githubKeyInternal, oauthClientSecretInternal, oauthRefreshInternal, parseExpiry, staleAt } from '../src/dynamic.js';
import { runWithSecrets } from '../src/inject.js';
import { mergeProfile } from '../src/profile.js';
import { MemoryBackend, SecretStore } from '../src/store.js';
import { Stubs } from './stubs.js';

let stubs: Stubs;
let backend: MemoryBackend;
let store: SecretStore;
const servers: Server[] = [];

beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-dyn-'));
  stubs = new Stubs();
  backend = new MemoryBackend();
  store = new SecretStore(backend, { providersConfig: {}, env: stubs.env() });
});
afterEach(() => { while (servers.length) servers.pop()!.close(); });

function body(req: IncomingMessage): Promise<string> {
  return new Promise(r => { let b = ''; req.on('data', d => { b += d; }); req.on('end', () => r(b)); });
}

async function serve(handler: (req: IncomingMessage, body: string) => { status: number; json: unknown }): Promise<string> {
  const server = createServer(async (req, res) => {
    const out = handler(req, await body(req));
    res.writeHead(out.status, { 'content-type': 'application/json' }).end(JSON.stringify(out.json));
  });
  servers.push(server);
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

describe('expiry handling', () => {
  it('parses ISO, epoch seconds and epoch ms', () => {
    expect(parseExpiry('2030-01-01T00:00:00Z')).toBe(Date.UTC(2030, 0, 1));
    expect(parseExpiry(1893456000)).toBe(1893456000000);
    expect(parseExpiry('1893456000000')).toBe(1893456000000);
    expect(parseExpiry('nonsense')).toBeUndefined();
  });

  it('refreshes before expiry by max(60 s, 10 %)', () => {
    const now = 1_000_000;
    expect(staleAt({ values: {}, expiresAt: now + 3_600_000 }, now)).toBe(now + 3_600_000 - 360_000);
    expect(staleAt({ values: {}, expiresAt: now + 120_000 }, now)).toBe(now + 60_000);
    expect(staleAt({ values: {} }, now)).toBe(now);
  });
});

describe('aws-sso bundle', () => {
  const creds = (id: string) => JSON.stringify({ Version: 1, AccessKeyId: id, SecretAccessKey: 'fake-secret-access-key-123', SessionToken: 'fake-session-token-456', Expiration: new Date(Date.now() + 3600e3).toISOString() });

  it('mints once, caches, injects all variables and redacts them', async () => {
    stubs.add('aws', [{ match: ['configure', 'export-credentials', '--profile', 'dev', '--format', 'process'], stdout: creds('AKIAFAKE0001') }]);
    store.defineDynamic('aws-dev', { type: 'aws-sso', options: { profile: 'dev' } });
    const r = await runWithSecrets(store, {
      command: [process.execPath, '-e', 'console.log([process.env.AWS_ACCESS_KEY_ID, process.env.AWS_SECRET_ACCESS_KEY, process.env.AWS_SESSION_TOKEN].join(" "))'],
      bundles: ['aws-dev'],
    });
    expect(r.stdout.trim()).toBe('[tresor:aws-dev.AWS_ACCESS_KEY_ID] [tresor:aws-dev.AWS_SECRET_ACCESS_KEY] [tresor:aws-dev.AWS_SESSION_TOKEN]');
    await store.resolveBundle('aws-dev');
    expect(stubs.calls('aws')).toHaveLength(1);
  });

  it('refuses single-value use and explains expired SSO sessions', async () => {
    stubs.add('aws', [{ match: ['configure'], stderr: 'Error when retrieving token from sso: Token has expired and refresh failed', code: 255 }]);
    store.defineDynamic('aws-dev', { type: 'aws-sso', options: { profile: 'dev' } });
    await expect(store.resolve('aws-dev')).rejects.toThrow(/bundle/);
    await expect(store.resolveBundle('aws-dev')).rejects.toThrow(/aws sso login --profile dev/);
  });

  it('comes in through the project profile', async () => {
    stubs.add('aws', [{ match: ['configure'], stdout: creds('AKIAFAKE0002') }]);
    store.defineDynamic('aws-dev', { type: 'aws-sso', options: { profile: 'dev' } });
    const dir = mkdtempSync(join(tmpdir(), 'tresor-dyn-proj-'));
    const p = mergeProfile(dir, {}, [], ['aws-dev']);
    expect(p.bundles).toEqual(['aws-dev']);
  });
});

describe('cloud CLIs', () => {
  it('gcloud: token with ~55 min cache, prompts disabled', async () => {
    stubs.add('gcloud', [{ match: ['auth', 'print-access-token', '--impersonate-service-account=ci@p.iam.gserviceaccount.com', '--quiet'], stdout: 'ya29.fake-token\n' }]);
    store.defineDynamic('gcp', { type: 'gcloud', options: { impersonate: 'ci@p.iam.gserviceaccount.com' } });
    expect(await store.resolve('gcp')).toBe('ya29.fake-token');
    expect(await store.resolve('gcp')).toBe('ya29.fake-token');
    expect(stubs.calls('gcloud')).toHaveLength(1);
  });

  it('azure: accessToken with expires_on', async () => {
    const exp = Math.floor(Date.now() / 1000) + 3000;
    stubs.add('az', [{ match: ['account', 'get-access-token', '--resource', 'https://management.azure.com/', '-o', 'json'], stdout: JSON.stringify({ accessToken: 'eyFAKE', expires_on: exp }) }]);
    store.defineDynamic('arm', { type: 'azure', options: { resource: 'https://management.azure.com/' } });
    expect(await store.resolve('arm')).toBe('eyFAKE');
  });

  it('command: JSON outputs as a bundle with lease-based TTL', async () => {
    stubs.add('vault', [{ match: ['read', '-format=json', 'database/creds/app'], stdout: JSON.stringify({ lease_duration: 3600, data: { username: 'v-app-1', password: 'fake-db-pw-998877' } }) }]);
    store.defineDynamic('db', { type: 'command', options: { argv: ['vault', 'read', '-format=json', 'database/creds/app'], outputs: { PGUSER: 'data.username', PGPASSWORD: 'data.password' }, ttlPath: 'lease_duration' } });
    expect(await store.resolveBundle('db')).toEqual({ PGUSER: 'v-app-1', PGPASSWORD: 'fake-db-pw-998877' });
    await store.resolveBundle('db');
    expect(stubs.calls('vault')).toHaveLength(1);
  });

  it('command: raw output without expiry is minted on every use', async () => {
    stubs.add('mint', [{ match: [], stdout: 'raw-token-value-1\n' }]);
    store.defineDynamic('raw', { type: 'command', options: { argv: ['mint'] } });
    await store.resolve('raw');
    await store.resolve('raw');
    expect(stubs.calls('mint')).toHaveLength(2);
  });
});

describe('github-app', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();

  it('signs a valid RS256 JWT with drift-tolerant claims', () => {
    const jwt = githubAppJwt('12345', pem, 1_000_000);
    const [h, p, sig] = jwt.split('.');
    expect(JSON.parse(Buffer.from(h, 'base64url').toString())).toEqual({ alg: 'RS256', typ: 'JWT' });
    expect(JSON.parse(Buffer.from(p, 'base64url').toString())).toEqual({ iat: 999_940, exp: 1_000_540, iss: '12345' });
    expect(createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(sig, 'base64url'))).toBe(true);
  });

  it('exchanges the JWT for an installation token with optional scoping', async () => {
    let seen: { auth?: string; body?: string; url?: string } = {};
    const api = await serve((req, b) => {
      seen = { auth: req.headers.authorization, body: b, url: req.url };
      return { status: 201, json: { token: 'ghs_fakeInstallationToken', expires_at: new Date(Date.now() + 3600e3).toISOString() } };
    });
    store.defineDynamic('bot', { type: 'github-app', options: { appId: '42', installationId: '7', apiUrl: api, repositories: ['tresor'], permissions: { contents: 'read' } } });
    backend.set(`__internal.${githubKeyInternal('bot')}`, pem);
    expect(await store.resolve('bot')).toBe('ghs_fakeInstallationToken');
    expect(seen.url).toBe('/app/installations/7/access_tokens');
    expect(seen.auth).toMatch(/^Bearer ey/);
    expect(JSON.parse(seen.body!)).toEqual({ repositories: ['tresor'], permissions: { contents: 'read' } });
  });

  it('reports a missing key and HTTP errors clearly', async () => {
    store.defineDynamic('bot', { type: 'github-app', options: { appId: '42', installationId: '7', apiUrl: 'http://127.0.0.1:9' } });
    await expect(store.resolve('bot')).rejects.toThrow(/private key missing/);
    const api = await serve(() => ({ status: 404, json: { message: 'Not Found' } }));
    store.defineDynamic('bot', { type: 'github-app', options: { appId: '42', installationId: '7', apiUrl: api } });
    backend.set(`__internal.${githubKeyInternal('bot')}`, pem);
    await expect(store.resolve('bot')).rejects.toThrow(/404 Not Found \(installation not found\)/);
  });
});

describe('oauth refresh', () => {
  function setup(tokenUrl: string, authMethod = 'basic') {
    store.defineDynamic('crm', { type: 'oauth', options: { tokenUrl, clientId: 'cid', authMethod } });
    backend.set(`__internal.${oauthRefreshInternal('crm')}`, 'refresh-1');
    backend.set(`__internal.${oauthClientSecretInternal('crm')}`, 'csecret');
  }

  it('uses basic auth, stores rotated refresh tokens, and caches by expires_in', async () => {
    const requests: Array<{ auth?: string; form: URLSearchParams }> = [];
    let n = 0;
    const url = await serve((req, b) => {
      requests.push({ auth: req.headers.authorization, form: new URLSearchParams(b) });
      n++;
      return { status: 200, json: { access_token: `access-${n}`, refresh_token: `refresh-${n + 1}`, expires_in: n === 1 ? 30 : 3600 } };
    });
    setup(`${url}/token`);
    expect(await store.resolve('crm')).toBe('access-1');
    expect(backend.get(`__internal.${oauthRefreshInternal('crm')}`)).toBe('refresh-2');
    expect(requests[0].auth).toBe(`Basic ${Buffer.from('cid:csecret').toString('base64')}`);
    expect(requests[0].form.get('grant_type')).toBe('refresh_token');
    // 30 s lifetime is below the 60 s safety margin → refreshed again, with the rotated token
    expect(await store.resolve('crm')).toBe('access-2');
    expect(requests[1].form.get('refresh_token')).toBe('refresh-2');
    expect(await store.resolve('crm')).toBe('access-2');
    expect(requests).toHaveLength(2);
  });

  it('single-flights concurrent uses', async () => {
    let calls = 0;
    const url = await serve(() => { calls++; return { status: 200, json: { access_token: 'a', expires_in: 3600 } }; });
    setup(`${url}/token`, 'post');
    await Promise.all([store.resolve('crm'), store.resolve('crm'), store.resolve('crm')]);
    expect(calls).toBe(1);
  });

  it('explains invalid_grant and cleans up internal secrets on remove', async () => {
    const url = await serve(() => ({ status: 400, json: { error: 'invalid_grant', error_description: 'expired' } }));
    setup(`${url}/token`);
    await expect(store.resolve('crm')).rejects.toThrow(/refresh token is expired or revoked/);
    store.remove('crm');
    expect(backend.get(`__internal.${oauthRefreshInternal('crm')}`)).toBeNull();
    expect(backend.get(`__internal.${oauthClientSecretInternal('crm')}`)).toBeNull();
  });

  it('rejects plain http token endpoints except localhost', () => {
    expect(() => store.defineDynamic('x', { type: 'oauth', options: { tokenUrl: 'http://evil.example/token', clientId: 'c' } })).toThrow(/https/);
  });
});

describe('store rules', () => {
  it('keeps local, linked and dynamic secrets apart', () => {
    store.set('local', 'local-value-123');
    expect(() => store.defineDynamic('local', { type: 'gcloud', options: {} })).toThrow(/already exists/);
    store.defineDynamic('dyn', { type: 'gcloud', options: {} });
    expect(() => store.set('dyn', 'x-value-123')).toThrow(/dynamic/);
    expect(() => store.link('dyn', 'pass', 'a/b')).toThrow(/dynamic/);
    expect(() => store.defineDynamic('bad', { type: 'nope' as never, options: {} })).toThrow(/Unknown dynamic type/);
  });
});
