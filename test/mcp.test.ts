import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { existsSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { createServer, type Dialogs } from '../src/mcp.js';
import { MemoryBackend, SecretStore } from '../src/store.js';
import { Stubs } from './stubs.js';

const TOKEN = 'fake-gh-token-for-tests-0001';
const unexpected = async (): Promise<never> => { throw new Error('dialog not expected in this test'); };
type TextResult = { content: Array<{ text: string }>; isError?: boolean };

async function connect(store: SecretStore, dialogs: Partial<Dialogs> = {}) {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await createServer(store, { promptSecret: unexpected, confirm: unexpected, ...dialogs }).connect(a);
  const client = new Client({ name: 'test', version: '0' });
  await client.connect(b);
  const call = async (name: string, args: Record<string, unknown> = {}) =>
    (await client.callTool({ name, arguments: args })) as TextResult;
  return { client, call };
}

let store: SecretStore;
beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-mcp-'));
  store = new SecretStore(new MemoryBackend());
});

describe('MCP tools', () => {
  it('exposes no tool that could return or delete a value', async () => {
    const { client } = await connect(store);
    const names = (await client.listTools()).tools.map(t => t.name).sort();
    expect(names).toEqual(['tresor_http', 'tresor_link', 'tresor_list', 'tresor_providers', 'tresor_request', 'tresor_run', 'tresor_write_file']);
  });

  it('tresor_request stores the dialog value without returning it', async () => {
    const { call } = await connect(store, { promptSecret: async () => ({ status: 'ok', value: TOKEN }) });
    const r = await call('tresor_request', { name: 'github', description: 'PAT', hosts: ['API.github.com'] });
    expect(r.content[0].text).toBe('Secret "github" created.');
    expect(await store.resolve('github')).toBe(TOKEN);
    expect(store.meta('github')!.hosts).toEqual(['api.github.com']);
    expect(JSON.stringify(await call('tresor_list'))).not.toContain(TOKEN);
  });

  it('tresor_request reports cancel without storing', async () => {
    const { call } = await connect(store, { promptSecret: async () => ({ status: 'cancelled' }) });
    expect((await call('tresor_request', { name: 'x' })).content[0].text).toMatch(/cancelled/);
    expect(store.has('x')).toBe(false);
  });

  it('tresor_run returns redacted output end-to-end', async () => {
    store.set('github', TOKEN);
    const { call } = await connect(store);
    const r = await call('tresor_run', { command: [process.execPath, '-e', 'console.log("GH_TOKEN=" + process.env.GH_TOKEN)'], env: { GH_TOKEN: 'github' } });
    expect(r.isError).toBeFalsy();
    expect(r.content[0].text).toContain('GH_TOKEN=[tresor:github]');
    expect(r.content[0].text).not.toContain(TOKEN);
  });

  it('tresor_link asks for confirmation and never returns the value', async () => {
    const stubs = new Stubs().add('pass', [{ match: ['show', 'api/gh'], stdout: TOKEN }]);
    const linked = new SecretStore(new MemoryBackend(), { providersConfig: {}, env: stubs.env() });
    let asked = '';
    const { call } = await connect(linked, { confirm: async text => { asked = text; return 'yes'; } });
    const r = await call('tresor_link', { name: 'gh', provider: 'pass', ref: 'api/gh', hosts: ['api.github.com'] });
    expect(asked).toMatch(/"api\/gh" from pass as secret "gh"/);
    expect(r.content[0].text).toMatch(/Test fetch ok/);
    expect(r.content[0].text).not.toContain(TOKEN);
    expect(linked.meta('gh')).toMatchObject({ source: { provider: 'pass', ref: 'api/gh' }, hosts: ['api.github.com'] });
  });

  it('tresor_link does nothing when the user declines or the ref is invalid', async () => {
    const { call } = await connect(store, { confirm: async () => 'no' });
    expect((await call('tresor_link', { name: 'x', provider: 'pass', ref: 'a/b' })).content[0].text).toMatch(/declined/);
    expect(store.has('x')).toBe(false);
    const bad = await call('tresor_link', { name: 'x', provider: '1password', ref: 'nope' });
    expect(bad.isError).toBe(true);
  });

  it('tresor_providers lists all builtin managers', async () => {
    const { call } = await connect(store);
    const ids = (JSON.parse((await call('tresor_providers')).content[0].text) as Array<{ id: string }>).map(p => p.id);
    expect(ids).toEqual(['1password', 'bitwarden', 'bws', 'keepassxc', 'pass', 'gopass', 'lastpass']);
  });

  it('returns tool errors instead of crashing', async () => {
    const { call } = await connect(store);
    const r = await call('tresor_run', { command: [process.execPath, '-v'], env: { X: 'missing' } });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/Unknown secret/);
  });
});

describe('startup', () => {
  it('built server starts over stdio and lists tools', async () => {
    const entry = resolve('dist/server.js');
    expect(existsSync(entry), 'run npm run build first').toBe(true);
    const client = new Client({ name: 'startup', version: '0' });
    await client.connect(new StdioClientTransport({
      command: process.execPath, args: [entry],
      env: { ...process.env, TRESOR_HOME: process.env.TRESOR_HOME! } as Record<string, string>,
    }));
    const tools = await client.listTools();
    expect(tools.tools.length).toBe(7);
    const list = (await client.callTool({ name: 'tresor_list', arguments: {} })) as TextResult;
    expect(list.content[0].text).toBe('[]');
    await client.close();
  });
});
