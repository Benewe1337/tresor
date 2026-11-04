import { mkdtempSync, readFileSync, statSync } from 'fs';
import { createServer as createHttpServer, type Server } from 'http';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { httpWithSecrets, runWithSecrets, writeFileWithSecrets } from '../src/inject.js';
import { Redactor, truncate } from '../src/redact.js';
import { MemoryBackend, SecretStore } from '../src/store.js';
import { fill, placeholderNames } from '../src/template.js';

const TOKEN = 'fake-openai-token-for-tests';
let store: SecretStore;

beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-test-'));
  store = new SecretStore(new MemoryBackend());
  store.set('openai', TOKEN, { description: 'test key' });
});

describe('SecretStore', () => {
  it('lists metadata but never values', () => {
    const listed = JSON.stringify(store.list());
    expect(listed).toContain('openai');
    expect(listed).not.toContain(TOKEN);
    expect(readFileSync(join(process.env.TRESOR_HOME!, 'index.json'), 'utf-8')).not.toContain(TOKEN);
  });

  it('reports created vs updated and keeps createdAt', async () => {
    const created = store.meta('openai')!.createdAt;
    expect(store.set('openai', 'new-value-123')).toBe('updated');
    expect(store.meta('openai')!.createdAt).toBe(created);
    expect(await store.resolve('openai')).toBe('new-value-123');
  });

  it('rejects invalid names, empty values and unknown secrets', async () => {
    expect(() => store.set('bad name', 'x')).toThrow(/Invalid secret name/);
    expect(() => store.set('__internal.x', 'x')).toThrow(/Invalid secret name/);
    expect(() => store.set('ok', '')).toThrow(/empty/);
    await expect(store.resolve('nope')).rejects.toThrow(/Unknown secret "nope"/);
  });

  it('removes from index and backend', () => {
    expect(store.remove('openai')).toBe(true);
    expect(store.has('openai')).toBe(false);
    expect(store.remove('openai')).toBe(false);
  });
});

describe('Redactor', () => {
  it('redacts raw, base64, url-encoded and json-escaped forms', () => {
    const value = 'p@ss/w"ord+123';
    const r = new Redactor({ db: value });
    const b64 = Buffer.from(value).toString('base64');
    const out = r.redact(`raw=${value} b64=${b64} url=${encodeURIComponent(value)} json=${JSON.stringify(value)}`);
    expect(out).not.toContain(value);
    expect(out).not.toContain(b64);
    expect(out).not.toContain(encodeURIComponent(value));
    expect(out).toContain('[tresor:db]');
  });

  it('ignores values too short to redact safely', () => {
    expect(new Redactor({ pin: 'abc' }).redact('abcabc')).toBe('abcabc');
  });

  it('truncates long output with a marker', () => {
    const t = truncate('x'.repeat(1000), 100);
    expect(t.length).toBeLessThan(200);
    expect(t).toContain('truncated');
  });
});

describe('template', () => {
  it('finds and fills only namespaced placeholders', () => {
    const s = 'a {{secret:openai}} b {{ helm.value }} {{secret:openai}}';
    expect(placeholderNames(s)).toEqual(['openai']);
    expect(fill(s, { openai: 'X' })).toBe('a X b {{ helm.value }} X');
  });
});

describe('runWithSecrets', () => {
  it('injects env vars and redacts them from output', async () => {
    const r = await runWithSecrets(store, { command: [process.execPath, '-e', 'console.log("key=" + process.env.KEY); console.error(process.env.KEY)'], env: { KEY: 'openai' } });
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toBe('key=[tresor:openai]');
    expect(r.stderr).not.toContain(TOKEN);
  });

  it('substitutes arg placeholders and redacts base64 echoes', async () => {
    const r = await runWithSecrets(store, { command: [process.execPath, '-e', 'console.log(Buffer.from(process.argv[1]).toString("base64"))', '{{secret:openai}}'] });
    expect(r.stdout).toContain('[tresor:openai]');
    expect(r.stdout).not.toContain(Buffer.from(TOKEN).toString('base64'));
  });

  it('kills on timeout', async () => {
    const r = await runWithSecrets(store, { command: [process.execPath, '-e', 'setTimeout(() => {}, 5000)'], timeoutMs: 200 });
    expect(r.timedOut).toBe(true);
  });

  it('fails loudly on unknown secrets', async () => {
    await expect(runWithSecrets(store, { command: [process.execPath, '-v'], env: { X: 'missing' } })).rejects.toThrow(/Unknown secret/);
  });
});

describe('httpWithSecrets', () => {
  let server: Server;
  let base: string;
  beforeAll(async () => {
    server = createHttpServer((req, res) => {
      if (req.url === '/redirect') { res.writeHead(302, { location: 'https://evil.example/' }).end(); return; }
      res.writeHead(200, { 'x-echo': String(req.headers.authorization) }).end(`you sent ${req.headers.authorization}`);
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterAll(() => server.close());

  it('sends the secret and redacts the echoed response', async () => {
    const r = await httpWithSecrets(store, { url: `${base}/`, headers: { Authorization: 'Bearer {{secret:openai}}' } });
    expect(r.status).toBe(200);
    expect(r.body).toBe('you sent Bearer [tresor:openai]');
    expect(r.headers['x-echo']).toBe('Bearer [tresor:openai]');
  });

  it('does not follow redirects', async () => {
    const r = await httpWithSecrets(store, { url: `${base}/redirect`, headers: { 'x-api-key': '{{secret:openai}}' } });
    expect(r.status).toBe(302);
  });

  it('refuses plain http to remote hosts and enforces pinned hosts', async () => {
    await expect(httpWithSecrets(store, { url: 'http://example.com/?k={{secret:openai}}' })).rejects.toThrow(/https/);
    store.set('pinned', 'pinned-value-xyz', { hosts: ['api.openai.com'] });
    await expect(httpWithSecrets(store, { url: `${base}/`, headers: { a: '{{secret:pinned}}' } })).rejects.toThrow(/may only be sent to/);
  });

  it('requires at least one placeholder', async () => {
    await expect(httpWithSecrets(store, { url: `${base}/` })).rejects.toThrow(/No \{\{secret/);
  });
});

describe('writeFileWithSecrets', () => {
  it('writes mode 600 and registers the path for the guard', async () => {
    const path = join(process.env.TRESOR_HOME!, 'proj', '.env');
    const r = await writeFileWithSecrets(store, path, 'OPENAI_API_KEY={{secret:openai}}\n');
    expect(r.secrets).toEqual(['openai']);
    expect(readFileSync(path, 'utf-8')).toBe(`OPENAI_API_KEY=${TOKEN}\n`);
    if (process.platform !== 'win32') expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(readFileSync(join(process.env.TRESOR_HOME!, 'written-files.txt'), 'utf-8')).toContain(path);
  });
});
