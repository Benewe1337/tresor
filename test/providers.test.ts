import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { runWithSecrets } from '../src/inject.js';
import { BW_SESSION_KEY, BWS_TOKEN_KEY } from '../src/providers/bitwarden.js';
import { getProvider, allProviders, type ProvidersConfig } from '../src/providers/index.js';
import { KEEPASS_PASSWORD_KEY } from '../src/providers/keepassxc.js';
import { MemoryBackend, SecretStore } from '../src/store.js';
import { Stubs } from './stubs.js';

const VALUE = 'fake-provider-secret-value-777';
let stubs: Stubs;
let backend: MemoryBackend;

function makeStore(config: ProvidersConfig = {}, extraEnv: NodeJS.ProcessEnv = {}) {
  return new SecretStore(backend, { providersConfig: config, env: stubs.env(extraEnv) });
}

beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-prov-'));
  stubs = new Stubs();
  backend = new MemoryBackend();
});

describe('1Password', () => {
  it('reads a secret reference via op read', async () => {
    stubs.add('op', [{ match: ['read', '--no-newline', 'op://Private/OpenAI/credential'], stdout: VALUE }]);
    const store = makeStore();
    store.link('openai', '1password', 'op://Private/OpenAI/credential');
    expect(await store.resolve('openai')).toBe(VALUE);
  });

  it('rejects malformed refs and surfaces CLI errors', async () => {
    const store = makeStore();
    expect(() => store.link('x', '1password', 'Private/OpenAI')).toThrow(/op:\/\//);
    stubs.add('op', [{ match: ['read'], stderr: '[ERROR] item not found', code: 1 }]);
    store.link('x', '1password', 'op://a/b/c');
    await expect(store.resolve('x')).rejects.toThrow(/1Password: \[ERROR\] item not found/);
  });

  it('reports not installed when op is missing', async () => {
    const store = new SecretStore(backend, { providersConfig: {}, env: { PATH: stubs.dir } });
    const op = (await store.providerStatuses()).find(p => p.id === '1password')!;
    expect(op).toMatchObject({ installed: false, ready: false });
  });
});

describe('Bitwarden', () => {
  const item = { id: 'a1b2', name: 'GitHub', notes: 'n', login: { username: 'ben', password: VALUE, uris: [{ uri: 'https://github.com' }] }, fields: [{ name: 'token', value: 'field-value-123' }] };

  it('requires an unlocked session', async () => {
    const store = makeStore();
    store.link('gh', 'bitwarden', 'GitHub');
    await expect(store.resolve('gh')).rejects.toThrow(/tresor unlock bitwarden/);
  });

  it('uses the stored session and picks password, custom fields and totp', async () => {
    stubs.add('bw', [
      { match: ['get', 'item', 'GitHub'], stdout: JSON.stringify(item) },
      { match: ['get', 'totp', 'a1b2'], stdout: '123456\n' },
    ]);
    const store = makeStore();
    store.providerContext().internal.set(BW_SESSION_KEY, 'sess-xyz');
    store.link('gh', 'bitwarden', 'GitHub');
    store.link('gh-token', 'bitwarden', 'GitHub#token');
    store.link('gh-user', 'bitwarden', 'GitHub#username');
    store.link('gh-totp', 'bitwarden', 'GitHub#totp');
    expect(await store.resolve('gh')).toBe(VALUE);
    expect(await store.resolve('gh-token')).toBe('field-value-123');
    expect(await store.resolve('gh-user')).toBe('ben');
    expect(await store.resolve('gh-totp')).toBe('123456');
    expect(stubs.calls('bw').every(c => c.env.BW_SESSION === 'sess-xyz')).toBe(true);
    expect(stubs.calls('bw')[0].argv).toContain('--nointeraction');
  });

  it('refuses a search hit that is not an exact match', async () => {
    stubs.add('bw', [{ match: ['get', 'item', 'Git'], stdout: JSON.stringify(item) }]);
    const store = makeStore({}, { BW_SESSION: 'env-session' });
    store.link('g', 'bitwarden', 'Git');
    await expect(store.resolve('g')).rejects.toThrow(/no exact match/);
  });

  it('errors on unknown fields and reads status', async () => {
    stubs.add('bw', [
      { match: ['get', 'item', 'a1b2'], stdout: JSON.stringify(item) },
      { match: ['status'], stdout: JSON.stringify({ status: 'locked' }) },
    ]);
    const store = makeStore({}, { BW_SESSION: 's' });
    store.link('g', 'bitwarden', 'a1b2#nope');
    await expect(store.resolve('g')).rejects.toThrow(/no field "nope"/);
    const st = (await store.providerStatuses()).find(p => p.id === 'bitwarden')!;
    expect(st).toMatchObject({ installed: true, ready: false });
    expect(st.detail).toMatch(/locked/);
  });
});

describe('Bitwarden Secrets Manager', () => {
  const id = '0f8fad5b-d9cb-469f-a165-70867728950e';
  it('reads .value with the stored access token', async () => {
    stubs.add('bws', [{ match: ['secret', 'get', id, '--output', 'json'], stdout: JSON.stringify({ id, key: 'K', value: VALUE }) }]);
    const store = makeStore();
    store.providerContext().internal.set(BWS_TOKEN_KEY, 'tok-1');
    store.link('k', 'bws', id);
    expect(await store.resolve('k')).toBe(VALUE);
    expect(stubs.calls('bws')[0].env.BWS_ACCESS_TOKEN).toBe('tok-1');
    expect(() => store.link('bad', 'bws', 'not-a-uuid')).toThrow(/UUID/);
  });
});

describe('KeePassXC', () => {
  it('needs setup first', async () => {
    const store = makeStore();
    store.link('k', 'keepassxc', 'Web/GitHub');
    await expect(store.resolve('k')).rejects.toThrow(/tresor setup keepassxc/);
  });

  it('pipes the database password on stdin and selects attributes', async () => {
    const db = join(stubs.dir, 'x.kdbx');
    writeFileSync(db, '');
    stubs.add('keepassxc-cli', [
      { match: ['show', '-q', '-s', '-a', 'Password', db, 'Web/GitHub'], stdout: `${VALUE}\n` },
      { match: ['show', '-q', '-s', '--totp', db, 'Web/GitHub'], stdout: '654321\n' },
      { match: ['show', '-q', '-s', '-a', 'UserName', db, 'Web/GitHub'], stdout: 'ben\n' },
    ]);
    const store = makeStore({ keepassxc: { database: db } });
    store.providerContext().internal.set(KEEPASS_PASSWORD_KEY, 'db-pw');
    store.link('k', 'keepassxc', 'Web/GitHub');
    store.link('k-totp', 'keepassxc', 'Web/GitHub#totp');
    store.link('k-user', 'keepassxc', 'Web/GitHub#UserName');
    expect(await store.resolve('k')).toBe(VALUE);
    expect(await store.resolve('k-totp')).toBe('654321');
    expect(await store.resolve('k-user')).toBe('ben');
    const calls = stubs.calls('keepassxc-cli');
    expect(calls.every(c => c.stdin === 'db-pw\n')).toBe(true);
    expect(calls.some(c => c.argv.includes('db-pw'))).toBe(false);
  });

  it('supports key file without password', async () => {
    const db = join(stubs.dir, 'y.kdbx');
    writeFileSync(db, '');
    stubs.add('keepassxc-cli', [{ match: ['show', '-q', '-s', '-a', 'Password', '-k', '/k.key', '--no-password', db, 'E'], stdout: VALUE }]);
    const store = makeStore({ keepassxc: { database: db, keyFile: '/k.key', noPassword: true } });
    store.link('k', 'keepassxc', 'E');
    expect(await store.resolve('k')).toBe(VALUE);
  });
});

describe('pass, gopass, LastPass', () => {
  it('pass: first line or named field', async () => {
    stubs.add('pass', [{ match: ['show', 'api/openai'], stdout: `${VALUE}\nuser: ben\nurl: https://x\n` }]);
    const store = makeStore();
    store.link('p', 'pass', 'api/openai');
    store.link('pu', 'pass', 'api/openai#user');
    store.link('px', 'pass', 'api/openai#missing');
    expect(await store.resolve('p')).toBe(VALUE);
    expect(await store.resolve('pu')).toBe('ben');
    await expect(store.resolve('px')).rejects.toThrow(/no field "missing"/);
  });

  it('gopass: password only vs key', async () => {
    stubs.add('gopass', [
      { match: ['show', '-o', 'api/openai'], stdout: VALUE },
      { match: ['show', 'api/openai', 'user'], stdout: 'ben\n' },
    ]);
    const store = makeStore();
    store.link('g', 'gopass', 'api/openai');
    store.link('gu', 'gopass', 'api/openai#user');
    expect(await store.resolve('g')).toBe(VALUE);
    expect(await store.resolve('gu')).toBe('ben');
  });

  it('lastpass: maps fields to flags', async () => {
    stubs.add('lpass', [
      { match: ['show', '--password', 'Work/API'], stdout: VALUE },
      { match: ['show', '--field=Token', 'Work/API'], stdout: 'tok\n' },
    ]);
    const store = makeStore();
    store.link('l', 'lastpass', 'Work/API');
    store.link('lt', 'lastpass', 'Work/API#Token');
    expect(await store.resolve('l')).toBe(VALUE);
    expect(await store.resolve('lt')).toBe('tok');
  });
});

describe('custom providers', () => {
  it('substitutes {ref} and picks a JSON path', async () => {
    stubs.add('doppler', [{ match: ['secrets', 'get', 'OPENAI', '--json'], stdout: JSON.stringify({ OPENAI: { computed: VALUE } }) }]);
    const store = makeStore({ custom: { doppler: { command: ['doppler', 'secrets', 'get', '{ref}', '--json'], jsonPath: 'OPENAI.computed' } } });
    store.link('d', 'doppler', 'OPENAI');
    expect(await store.resolve('d')).toBe(VALUE);
  });

  it('rejects broken definitions and builtin collisions', () => {
    expect(() => allProviders({ custom: { x: { command: ['x', 'get'] } } })).toThrow(/\{ref\}/);
    expect(() => allProviders({ custom: { pass: { command: ['p', '{ref}'] } } })).toThrow(/collides/);
    expect(() => getProvider('nope', {})).toThrow(/Unknown provider/);
  });
});

describe('store semantics for linked secrets', () => {
  it('keeps local and linked secrets apart', () => {
    const store = makeStore();
    store.set('local', 'local-value-1');
    expect(() => store.link('local', 'pass', 'a/b')).toThrow(/stored locally/);
    store.link('linked', 'pass', 'a/b');
    expect(() => store.set('linked', 'x-value')).toThrow(/is linked/);
    expect(store.meta('linked')!.source).toEqual({ provider: 'pass', ref: 'a/b' });
    expect(store.remove('linked')).toBe(true);
    expect(backend.get('local')).toBe('local-value-1');
  });

  it('redacts provider values in tresor_run output', async () => {
    stubs.add('pass', [{ match: ['show', 'k'], stdout: VALUE }]);
    const store = makeStore();
    store.link('k', 'pass', 'k');
    const r = await runWithSecrets(store, { command: [process.execPath, '-e', 'console.log(process.env.K)'], env: { K: 'k' } });
    expect(r.stdout.trim()).toBe('[tresor:k]');
  });
});
