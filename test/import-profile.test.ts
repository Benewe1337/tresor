import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { looksSecret, planImport, runImport, secretNameFor } from '../src/import.js';
import { findProfile, isTrusted, mergeProfile, trustProfile } from '../src/profile.js';
import { MemoryBackend, SecretStore } from '../src/store.js';

let dir: string;
let store: SecretStore;

const ENV = `# app config
PORT=3000
DEBUG=true
OPENAI_API_KEY=sk-fake-import-0123456789
export DATABASE_URL=postgres://app:hunter2secret@db:5432/app
APP_NAME="My App"
OPAQUE=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MDEyMzQ1
MULTI_SECRET_KEY="line1
line2"
`;

beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-imp-home-'));
  dir = mkdtempSync(join(tmpdir(), 'tresor-imp-'));
  store = new SecretStore(new MemoryBackend(), { providersConfig: {} });
  writeFileSync(join(dir, '.env'), ENV);
});

describe('heuristics', () => {
  it('tells credentials from config', () => {
    expect(looksSecret('OPENAI_API_KEY', 'sk-x')).toBe(true);
    expect(looksSecret('DATABASE_URL', 'postgres://u:p@h/db')).toBe(true);
    expect(looksSecret('OPAQUE', 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MDEyMzQ1')).toBe(true);
    expect(looksSecret('PORT', '3000')).toBe(false);
    expect(looksSecret('DEBUG', 'true')).toBe(false);
    expect(looksSecret('APP_NAME', 'My App')).toBe(false);
    expect(looksSecret('API_KEY', '')).toBe(false);
  });

  it('derives secret names', () => {
    expect(secretNameFor('OPENAI_API_KEY')).toBe('openai-api-key');
    expect(secretNameFor('DATABASE_URL', 'shop')).toBe('shop-database-url');
  });
});

describe('import', () => {
  it('plans credentials only by default', () => {
    const plan = planImport(store, join(dir, '.env'));
    expect(plan.filter(p => p.selected).map(p => p.key)).toEqual(['OPENAI_API_KEY', 'DATABASE_URL', 'OPAQUE', 'MULTI_SECRET_KEY']);
  });

  it('stores values, writes the profile and strips single-line entries on --remove', async () => {
    const r = await runImport(store, join(dir, '.env'), { remove: true });
    expect(r.imported.map(i => i.name)).toEqual(['openai-api-key', 'database-url', 'opaque', 'multi-secret-key']);
    expect(await store.resolve('database-url')).toBe('postgres://app:hunter2secret@db:5432/app');
    expect(await store.resolve('multi-secret-key')).toBe('line1\nline2');
    const env = readFileSync(join(dir, '.env'), 'utf-8');
    expect(env).toContain('PORT=3000');
    expect(env).toContain('# app config');
    expect(env).not.toContain('sk-fake-import');
    expect(env).not.toContain('hunter2secret');
    expect(env).toContain('line2'); // multi-line left for the user
    expect(r.warnings.join()).toMatch(/multi-line/);
    expect(JSON.parse(readFileSync(join(dir, '.tresor.json'), 'utf-8')).env).toMatchObject({ OPENAI_API_KEY: 'openai-api-key', DATABASE_URL: 'database-url' });
  });

  it('honours --only, skips existing names unless --overwrite, and keeps the file without --remove', async () => {
    store.set('openai-api-key', 'old-value-1234');
    const r = await runImport(store, join(dir, '.env'), { only: ['OPENAI_API_KEY', 'PORT'] });
    expect(r.imported.map(i => i.key)).toEqual(['PORT']);
    expect(r.skipped[0]).toMatchObject({ key: 'OPENAI_API_KEY', reason: expect.stringMatching(/already exists/) });
    expect(readFileSync(join(dir, '.env'), 'utf-8')).toBe(ENV);
    const again = await runImport(store, join(dir, '.env'), { only: ['OPENAI_API_KEY'], overwrite: true });
    expect(again.imported).toHaveLength(1);
    expect(await store.resolve('openai-api-key')).toBe('sk-fake-import-0123456789');
  });
});

describe('profiles', () => {
  it('is found from subdirectories and needs re-trust after any change', () => {
    const p = mergeProfile(dir, { OPENAI_API_KEY: 'openai' });
    mkdirSync(join(dir, 'a', 'b'), { recursive: true });
    const found = findProfile(join(dir, 'a', 'b'))!;
    expect(found.path).toBe(p.path);
    expect(isTrusted(found)).toBe(false);
    trustProfile(found);
    expect(isTrusted(findProfile(dir)!)).toBe(true);
    mergeProfile(dir, { STRIPE_KEY: 'stripe' });
    expect(isTrusted(findProfile(dir)!)).toBe(false);
  });

  it('rejects malformed profiles and bad variable names', () => {
    writeFileSync(join(dir, '.tresor.json'), '{"env": ["x"]}');
    expect(() => findProfile(dir)).toThrow(/expected/);
    expect(() => mergeProfile(mkdtempSync(join(tmpdir(), 'p-')), { 'BAD-NAME': 'x' })).toThrow(/Invalid environment variable/);
  });
});
