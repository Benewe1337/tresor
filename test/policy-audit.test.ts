import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { readAudit } from '../src/audit.js';
import { createServer, type Dialogs } from '../src/mcp.js';
import { mergeProfile } from '../src/profile.js';
import { MemoryBackend, SecretStore } from '../src/store.js';

const TOKEN = 'fake-policy-token-987654321';
type TextResult = { content: Array<{ text: string }>; isError?: boolean };
let store: SecretStore;

async function connect(dialogs: Partial<Dialogs> = {}) {
  const [a, b] = InMemoryTransport.createLinkedPair();
  const never = async (): Promise<never> => { throw new Error('dialog not expected'); };
  await createServer(store, { promptSecret: never, confirm: never, ...dialogs }).connect(a);
  const client = new Client({ name: 't', version: '0' });
  await client.connect(b);
  return async (name: string, args: Record<string, unknown> = {}) => (await client.callTool({ name, arguments: args })) as TextResult;
}

const node = (code: string) => [process.execPath, '-e', code];

beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-pol-'));
  store = new SecretStore(new MemoryBackend(), { providersConfig: {} });
  store.set('gh', TOKEN);
});

describe('policies', () => {
  it('allowCommands restricts tresor_run and forbids writing files', async () => {
    store.updatePolicy('gh', { policy: { allowCommands: ['gh'] } });
    const call = await connect();
    const denied = await call('tresor_run', { command: node('1'), env: { T: 'gh' } });
    expect(denied.isError).toBe(true);
    expect(denied.content[0].text).toMatch(/may only be used with: gh \(not "node"\)/);
    const write = await call('tresor_write_file', { path: join(process.env.TRESOR_HOME!, 'x.env'), content: 'T={{secret:gh}}' });
    expect(write.content[0].text).toMatch(/may not be written to files/);
  });

  it('confirm=session asks once, confirm=always every time, and a "no" blocks', async () => {
    let asked = 0;
    let answer: 'yes' | 'no' = 'yes';
    const call = await connect({ confirm: async () => { asked++; return answer; } });
    store.updatePolicy('gh', { policy: { confirm: 'session' } });
    await call('tresor_run', { command: node('1'), env: { T: 'gh' } });
    await call('tresor_run', { command: node('1'), env: { T: 'gh' } });
    expect(asked).toBe(1);
    store.updatePolicy('gh', { policy: { confirm: 'always' } });
    await call('tresor_run', { command: node('1'), env: { T: 'gh' } });
    expect(asked).toBe(2);
    answer = 'no';
    const r = await call('tresor_run', { command: node('1'), env: { T: 'gh' } });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/did not allow/);
  });

  it('expired secrets still work but come with a rotation warning', async () => {
    store.updatePolicy('gh', { policy: { expiresAt: '2020-01-01T00:00:00.000Z' } });
    const call = await connect();
    const r = JSON.parse((await call('tresor_run', { command: node('console.log(process.env.T)'), env: { T: 'gh' } })).content[0].text);
    expect(r.stdout.trim()).toBe('[tresor:gh]');
    expect(r.warnings[0]).toMatch(/expired on 2020-01-01/);
  });

  it('updatePolicy merges, clears and preserves fields', () => {
    store.updatePolicy('gh', { hosts: ['API.github.com'], policy: { allowCommands: ['gh'], confirm: 'always' } });
    store.updatePolicy('gh', { policy: { confirm: undefined } });
    expect(store.meta('gh')).toMatchObject({ hosts: ['api.github.com'], policy: { allowCommands: ['gh'] } });
    store.updatePolicy('gh', { hosts: null, policy: { allowCommands: [] } });
    expect(store.meta('gh')!.hosts).toBeUndefined();
    expect(store.meta('gh')!.policy).toBeUndefined();
    store.set('gh', 'new-value-123456'); // re-setting keeps the policy
    store.updatePolicy('gh', { policy: { confirm: 'session' } });
    store.set('gh', 'newer-value-123456');
    expect(store.meta('gh')!.policy).toEqual({ confirm: 'session' });
  });
});

describe('audit log', () => {
  it('records allowed and refused uses without values', async () => {
    const call = await connect();
    await call('tresor_run', { command: node('console.log(process.env.T)'), env: { T: 'gh' } });
    store.updatePolicy('gh', { policy: { allowCommands: ['gh'] } });
    await call('tresor_run', { command: node('1'), env: { T: 'gh' } });
    const log = readAudit();
    expect(log.map(e => [e.action, e.ok])).toEqual([['run', true], ['run', false]]);
    expect(log[1].error).toMatch(/may only be used/);
    expect(JSON.stringify(log)).not.toContain(TOKEN);
    const viaTool = JSON.parse((await call('tresor_log', { secret: 'gh' })).content[0].text);
    expect(viaTool).toHaveLength(2);
  });
});

describe('project profile in tresor_run', () => {
  it('asks once to trust the profile, then injects its mappings', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tresor-proj-'));
    mergeProfile(dir, { GH_TOKEN: 'gh' });
    let asked = '';
    const call = await connect({ confirm: async t => { asked = t; return 'yes'; } });
    const r = JSON.parse((await call('tresor_run', { command: node('console.log(process.env.GH_TOKEN)'), cwd: dir })).content[0].text);
    expect(asked).toMatch(/GH_TOKEN ← gh/);
    expect(r.stdout.trim()).toBe('[tresor:gh]');
    expect(r.injected).toEqual(['GH_TOKEN']);
    asked = '';
    await call('tresor_run', { command: node('1'), cwd: dir });
    expect(asked).toBe('');
  });

  it('refuses an untrusted profile when the user declines, but runs with useProfile=false', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tresor-proj-'));
    mergeProfile(dir, { GH_TOKEN: 'gh' });
    const call = await connect({ confirm: async () => 'no' });
    const r = await call('tresor_run', { command: node('1'), cwd: dir });
    expect(r.content[0].text).toMatch(/not trusted/);
    const ok = JSON.parse((await call('tresor_run', { command: node('console.log(process.env.GH_TOKEN ?? "none")'), cwd: dir, useProfile: false })).content[0].text);
    expect(ok.stdout.trim()).toBe('none');
  });
});

describe('MCP import + scan', () => {
  it('imports a .env and finds the leaked value afterwards', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tresor-mcp-imp-'));
    writeFileSync(join(dir, '.env'), 'STRIPE_SECRET_KEY=fake-stripe-secret-0011223344\nPORT=1\n');
    writeFileSync(join(dir, 'leak.ts'), 'const k = "fake-stripe-secret-0011223344";\n');
    const call = await connect();
    const imp = JSON.parse((await call('tresor_import', { path: join(dir, '.env'), remove: true })).content[0].text);
    expect(imp.imported).toEqual([{ key: 'STRIPE_SECRET_KEY', name: 'stripe-secret-key' }]);
    const scan = await call('tresor_scan', { paths: [dir] });
    expect(scan.content[0].text).not.toContain('fake-stripe-secret');
    const report = JSON.parse(scan.content[0].text);
    expect(report.verdict).toMatch(/LEAK FOUND/);
    expect(report.findings.map((f: { file: string }) => f.file)).toEqual([join(dir, 'leak.ts')]);
  });
});
