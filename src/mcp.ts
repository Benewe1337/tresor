
/**
 * tresor MCP server. Deliberately has NO tool that returns a secret value and no
 * delete tool — removing secrets is a human-only action via the `tresor` CLI.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { httpWithSecrets, runWithSecrets, writeFileWithSecrets } from './inject.js';
import { promptSecret } from './prompt.js';
import { KeychainBackend, SecretStore, validateName } from './store.js';

type Prompt = typeof promptSecret;

const text = (value: unknown) => ({
  content: [{ type: 'text' as const, text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }],
});

async function guarded<T>(fn: () => Promise<T> | T) {
  try {
    return text(await fn());
  } catch (err) {
    return { ...text(`Error: ${err instanceof Error ? err.message : String(err)}`), isError: true };
  }
}

const PLACEHOLDER_HINT = 'Reference secrets as {{secret:NAME}}.';

export function createServer(store: SecretStore, prompt: Prompt = promptSecret): McpServer {
  const server = new McpServer({ name: 'tresor', version: '0.1.0' });

  server.registerTool('tresor_list', {
    description: 'List stored secrets (names, descriptions, allowed hosts, timestamps). Never returns values.',
    inputSchema: {},
  }, () => guarded(() => store.list()));

  server.registerTool('tresor_request', {
    description: 'Ask the user to enter a secret in a native macOS dialog. The value goes straight into the Keychain; you only learn whether it was saved. Use this whenever a token is needed that is not stored yet — never ask the user to paste a token into the chat.',
    inputSchema: {
      name: z.string().describe('Secret name, e.g. "openai" or "github-ci" (letters, digits, _ - .)'),
      description: z.string().max(300).optional().describe('What it is / where to get it, shown in the dialog'),
      hosts: z.array(z.string()).optional().describe('Restrict http injection to these hostnames, e.g. ["api.openai.com"]'),
    },
  }, ({ name, description, hosts }) => guarded(async () => {
    validateName(name);
    const r = await prompt(name, description);
    if (r.status !== 'ok') return `Not saved (${r.status === 'timeout' ? 'dialog timed out' : 'user cancelled'}).`;
    const action = store.set(name, r.value, { description, hosts });
    return `Secret "${name}" ${action}.`;
  }));

  server.registerTool('tresor_run', {
    description: `Run a command with secrets injected as environment variables (preferred) or into args. stdout/stderr are returned with every secret value redacted. No shell: for pipes or $VARS use ["sh","-c","..."]. ${PLACEHOLDER_HINT}`,
    inputSchema: {
      command: z.array(z.string()).min(1).describe('argv, e.g. ["gh","api","user"]'),
      env: z.record(z.string(), z.string()).optional().describe('ENV_VAR → secret name, e.g. {"GH_TOKEN":"github"}'),
      cwd: z.string().optional(),
      timeoutMs: z.number().int().positive().max(600_000).optional(),
    },
  }, input => guarded(() => runWithSecrets(store, input)));

  server.registerTool('tresor_http', {
    description: `HTTPS request with secrets substituted into url/headers/body. Response is redacted; redirects are not followed. ${PLACEHOLDER_HINT} Example header: {"Authorization":"Bearer {{secret:openai}}"}`,
    inputSchema: {
      url: z.string(),
      method: z.string().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      body: z.string().optional(),
      timeoutMs: z.number().int().positive().max(600_000).optional(),
    },
  }, input => guarded(() => httpWithSecrets(store, input)));

  server.registerTool('tresor_write_file', {
    description: `Write a file (mode 600) with secrets filled in, e.g. a .env. The file is registered so you cannot read it back. Make sure it is gitignored. ${PLACEHOLDER_HINT}`,
    inputSchema: {
      path: z.string(),
      content: z.string().describe('e.g. "OPENAI_API_KEY={{secret:openai}}\\n"'),
    },
  }, ({ path, content }) => guarded(() => writeFileWithSecrets(store, path, content)));

  return server;
}

export async function main(): Promise<void> {
  const server = createServer(new SecretStore(new KeychainBackend()));
  await server.connect(new StdioServerTransport());
}
