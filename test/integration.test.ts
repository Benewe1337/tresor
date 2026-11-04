/**
 * Real-system tests, opt-in via TRESOR_INTEGRATION=1 (CI, Docker). Uses the actual
 * OS credential store and — where installed — real pass/gpg and keepassxc-cli with
 * throwaway stores. Every entry it creates is removed again.
 */

import { execFileSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterAll, describe, expect, it } from 'vitest';
import { onPath } from '../src/platform/exec.js';
import { KEEPASS_PASSWORD_KEY } from '../src/providers/keepassxc.js';
import { KeychainBackend, MemoryBackend, SecretStore } from '../src/store.js';

const enabled = process.env.TRESOR_INTEGRATION === '1';
const VALUE = `it-value-${Date.now()}-äöü-🔑`;
const temp = mkdtempSync(join(tmpdir(), 'tresor-it-'));
afterAll(() => rmSync(temp, { recursive: true, force: true }));

describe.runIf(enabled)('OS credential store', () => {
  const backend = new KeychainBackend(`tresor-it-${process.pid}`);
  it('round-trips, updates and deletes a value', () => {
    backend.set('probe', VALUE);
    expect(backend.get('probe')).toBe(VALUE);
    backend.set('probe', `${VALUE}-2`);
    expect(backend.get('probe')).toBe(`${VALUE}-2`);
    expect(backend.delete('probe')).toBe(true);
    expect(backend.get('probe')).toBeNull();
  });
});

describe.runIf(enabled && onPath('pass') && onPath('gpg'))('pass (real gpg)', () => {
  it('resolves first line and fields', async () => {
    const env = { ...process.env, GNUPGHOME: join(temp, 'gnupg'), PASSWORD_STORE_DIR: join(temp, 'store') };
    execFileSync('mkdir', ['-p', env.GNUPGHOME!], { env });
    execFileSync('chmod', ['700', env.GNUPGHOME!], { env });
    execFileSync('gpg', ['--batch', '--passphrase', '', '--quick-gen-key', 'tresor-it@example.invalid', 'default', 'default', 'never'], { env, stdio: 'ignore' });
    execFileSync('pass', ['init', 'tresor-it@example.invalid'], { env, stdio: 'ignore' });
    execFileSync('pass', ['insert', '-m', 'api/openai'], { env, input: `${VALUE}\nuser: ben\n`, stdio: ['pipe', 'ignore', 'ignore'] });
    const store = new SecretStore(new MemoryBackend(), { indexFile: join(temp, 'idx-pass.json'), providersConfig: {}, env });
    store.link('p', 'pass', 'api/openai');
    store.link('pu', 'pass', 'api/openai#user');
    expect(await store.resolve('p')).toBe(VALUE);
    expect(await store.resolve('pu')).toBe('ben');
  }, 60_000);
});

describe.runIf(enabled && onPath('keepassxc-cli'))('KeePassXC (real database)', () => {
  it('resolves password and attributes from a fresh database', async () => {
    const db = join(temp, 'it.kdbx');
    const pw = 'db-pass-123';
    execFileSync('keepassxc-cli', ['db-create', '-q', '-p', db], { input: `${pw}\n${pw}\n` });
    execFileSync('keepassxc-cli', ['mkdir', '-q', db, 'Web'], { input: `${pw}\n` });
    execFileSync('keepassxc-cli', ['add', '-q', '-u', 'ben', '-p', db, 'Web/GitHub'], { input: `${pw}\n${VALUE}\n${VALUE}\n` });
    const backend = new MemoryBackend();
    const store = new SecretStore(backend, { indexFile: join(temp, 'idx-kp.json'), providersConfig: { keepassxc: { database: db } } });
    store.providerContext().internal.set(KEEPASS_PASSWORD_KEY, pw);
    store.link('k', 'keepassxc', 'Web/GitHub');
    store.link('ku', 'keepassxc', 'Web/GitHub#UserName');
    expect(await store.resolve('k')).toBe(VALUE);
    expect(await store.resolve('ku')).toBe('ben');
  }, 60_000);
});
