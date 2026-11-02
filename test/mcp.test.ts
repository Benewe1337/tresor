import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { existsSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { createServer } from '../src/mcp.js';
import { MemoryBackend, SecretStore } from '../src/store.js';

const TOKEN = 'fake-gh-token-for-tests-0001';
type TextResult = { content: Array<{ text: string }>; isError?: boolean };

async function connect(store: SecretStore, prompt?: Parameters<typeof createServer>[1]) {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await createServer(store, prompt).connect(a);
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
    expect(names).toEqual(['tresor_http', 'tresor_list', 'tresor_request', 'tresor_run', 'tresor_write_file']);
  });

  it('tresor_request stores the dialog value without returning it', async () => {
    const { call } = await connect(store, async () => ({ status: 'ok', value: TOKEN }));
    const r = await call('tresor_request', { name: 'github', description: 'PAT', hosts: ['API.github.com'] });
    expect(r.content[0].text).toBe('Secret "github" created.');
    expect(store.resolve('github')).toBe(TOKEN);
    expect(store.meta('github')!.hosts).toEqual(['api.github.com']);
    expect(JSON.stringify(await call('tresor_list'))).not.toContain(TOKEN);
  });

  it('tresor_request reports cancel without storing', async () => {
    const { call } = await connect(store, async () => ({ status: 'cancelled' }));
    expect((await call('tresor_request', { name: 'x' })).content[0].text).toMatch(/cancelled/);
    expect(store.has('x')).toBe(false);
  });

  it('tresor_run returns redacted output end-to-end', async () => {
    store.set('github', TOKEN);
    const { call } = await connect(store);
    const r = await call('tresor_run', { command: ['sh', '-c', 'env | grep GH_TOKEN'], env: { GH_TOKEN: 'github' } });
    expect(r.isError).toBeFalsy();
    expect(r.content[0].text).toContain('GH_TOKEN=[tresor:github]');
    expect(r.content[0].text).not.toContain(TOKEN);
  });

  it('returns tool errors instead of crashing', async () => {
    const { call } = await connect(store);
    const r = await call('tresor_run', { command: ['true'], env: { X: 'missing' } });
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
    expect(tools.tools.length).toBe(5);
    const list = (await client.callTool({ name: 'tresor_list', arguments: {} })) as TextResult;
    expect(list.content[0].text).toBe('[]');
    await client.close();
  });
});
