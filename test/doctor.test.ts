import { mkdirSync, mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { appendAudit } from '../src/audit.js';
import { formatDoctor, rotateUrlFor, runDoctor } from '../src/doctor.js';
import { MemoryBackend, SecretStore } from '../src/store.js';
import { Stubs } from './stubs.js';

const DAY = 86_400_000;
let backend: MemoryBackend;
let store: SecretStore;
const later = (d: number) => new Date(Date.now() + d * DAY);

beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-doc-'));
  backend = new MemoryBackend();
  store = new SecretStore(backend, { providersConfig: {}, env: { PATH: new Stubs().dir } });
});

describe('tresor doctor', () => {
  it('is quiet for fresh, used, pinned secrets', async () => {
    store.set('openai', 'sk-fake-doctor-1234', { hosts: ['api.openai.com'] });
    appendAudit({ via: 'mcp', action: 'run', secrets: ['openai'], detail: 'x', ok: true });
    expect(await runDoctor(store)).toEqual([]);
    expect(formatDoctor([], 1)).toMatch(/nothing to do/);
  });

  it('flags expired, expiring, old and unused secrets with rotation links', async () => {
    store.set('github-token', 'ghp-fake-123456');
    store.set('stripe', 'sk-fake-stripe-1', { hosts: ['api.stripe.com'] });
    store.updatePolicy('stripe', { policy: { expiresAt: later(5).toISOString() } });
    store.set('legacy', 'old-value-123456');
    store.updatePolicy('legacy', { policy: { expiresAt: later(-1).toISOString() } });

    const f = await runDoctor(store, { now: later(200) });
    const by = (s: string) => f.filter(x => x.secret === s);
    expect(by('legacy')[0]).toMatchObject({ level: 'error', message: expect.stringMatching(/expired/) });
    expect(by('stripe')[0]).toMatchObject({ level: 'error' }); // 200 days later it is expired too
    expect(by('github-token').map(x => x.message)).toEqual(expect.arrayContaining([
      expect.stringMatching(/never replaced/), expect.stringMatching(/never used/), 'not pinned to a host',
    ]));
    expect(by('github-token').find(x => /never replaced/.test(x.message))!.rotateUrl).toBe('https://github.com/settings/tokens');

    const soon = await runDoctor(store, { now: later(1) });
    expect(soon.find(x => x.secret === 'stripe')).toMatchObject({ level: 'warn', message: expect.stringMatching(/expires in \d day/) });
    expect(f[0].level).toBe('error'); // sorted by severity
  });

  it('reports values missing from the keychain and locked password managers', async () => {
    store.set('gone', 'value-12345678');
    backend.delete('gone');
    store.link('vaulted', 'bitwarden', 'Item');
    const f = await runDoctor(store);
    expect(f.find(x => x.secret === 'gone')).toMatchObject({ level: 'error', message: expect.stringMatching(/missing from the OS credential store/) });
    expect(f.find(x => x.secret === 'vaulted')).toMatchObject({ level: 'warn', message: expect.stringMatching(/Bitwarden is not ready/) });
  });

  it('finds leaks in transcripts', async () => {
    const claudeDir = mkdtempSync(join(tmpdir(), 'claude-'));
    mkdirSync(join(claudeDir, 'projects', 'p'), { recursive: true });
    writeFileSync(join(claudeDir, 'projects', 'p', 's.jsonl'), `${JSON.stringify({ text: 'key sk-fake-leaked-99887766' })}\n`);
    process.env.CLAUDE_CONFIG_DIR = claudeDir;
    try {
      store.set('openai', 'sk-fake-leaked-99887766', { hosts: ['api.openai.com'] });
      appendAudit({ via: 'cli', action: 'run', secrets: ['openai'], detail: 'x', ok: true });
      const f = await runDoctor(store, { transcripts: true });
      expect(f).toEqual([expect.objectContaining({ level: 'error', secret: 'openai', message: expect.stringMatching(/appears 1× in agent transcripts/), rotateUrl: 'https://platform.openai.com/api-keys' })]);
      expect(formatDoctor(f, 1)).not.toContain('sk-fake-leaked');
    } finally {
      delete process.env.CLAUDE_CONFIG_DIR;
    }
  });

  it('maps well-known services to rotation pages', () => {
    expect(rotateUrlFor('x', { hosts: ['api.anthropic.com'] })).toBe('https://console.anthropic.com/settings/keys');
    expect(rotateUrlFor('vercel', {})).toBe('https://vercel.com/account/tokens');
    expect(rotateUrlFor('internal-db', {})).toBeUndefined();
  });
});
