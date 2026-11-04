/**
 * tresor MCP server. Deliberately has NO tool that returns a secret value and no
 * delete tool — removing secrets is a human-only action via the `tresor` CLI.
 * Linking a password-manager entry always needs the user's OK in a native dialog.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { httpWithSecrets, runWithSecrets, writeFileWithSecrets } from './inject.js';
import { confirm, promptSecret } from './platform/prompt.js';
import { getProvider } from './providers/index.js';
import { KeychainBackend, SecretStore, validateName } from './store.js';

export interface Dialogs {
  promptSecret: typeof promptSecret;
  confirm: typeof confirm;
}

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

const SERVER_INSTRUCTIONS = `tresor holds the user's API tokens. You can USE them but never SEE them.
- Need a token? tresor_list first. Missing → tresor_request (user types it into a native dialog) or, if it lives in a password manager, tresor_providers + tresor_link (user confirms in a dialog). Never ask the user to paste a token into the chat.
- Use tokens only through tresor_run (env vars), tresor_http ({{secret:NAME}} placeholders) or tresor_write_file (.env etc.). Output comes back with values replaced by [tresor:NAME].
- Never try to read values another way (keychain CLIs, password-manager CLIs, printing env vars, reading files tresor wrote); a guard hook blocks this and it defeats the purpose.
- Errors like "Bitwarden is locked" or "not set up" need the user: tell them the exact command to run in their own terminal.`;

const PLACEHOLDER_HINT ='Reference secrets as {{secret:NAME}}.';
const HOSTS = z.array(z.string()).optional().describe('Restrict http injection to these hostnames, e.g. ["api.openai.com"]');

export function createServer(store: SecretStore, dialogs: Dialogs = { promptSecret, confirm }): McpServer {
  const server = new McpServer({ name: 'tresor', version: '0.3.0' }, { instructions: SERVER_INSTRUCTIONS });

  server.registerTool('tresor_list', {
    description: 'List secrets: names, descriptions, allowed hosts, and for linked ones the password manager + reference. Never returns values.',
    inputSchema: {},
  }, () => guarded(() => store.list()));

  server.registerTool('tresor_providers', {
    description: 'Show which password managers are installed/unlocked (1Password, Bitwarden, Bitwarden Secrets Manager, KeePassXC, pass, gopass, LastPass, custom) and their reference syntax for tresor_link.',
    inputSchema: {},
  }, () => guarded(() => store.providerStatuses()));

  server.registerTool('tresor_request', {
    description: 'Ask the user to enter a secret in a native dialog. The value goes straight into the OS credential store (Keychain / Windows Credential Manager / Secret Service); you only learn whether it was saved. Use this whenever a token is needed that is not stored yet — never ask the user to paste a token into the chat.',
    inputSchema: {
      name: z.string().describe('Secret name, e.g. "openai" or "github-ci" (letters, digits, _ - .)'),
      description: z.string().max(300).optional().describe('What it is / where to get it, shown in the dialog'),
      hosts: HOSTS,
    },
  }, ({ name, description, hosts }) => guarded(async () => {
    validateName(name);
    const r = await dialogs.promptSecret(name, description);
    if (r.status !== 'ok') return `Not saved (${r.status === 'timeout' ? 'dialog timed out' : 'user cancelled'}).`;
    const action = store.set(name, r.value, { description, hosts });
    return `Secret "${name}" ${action}.`;
  }));

  server.registerTool('tresor_link', {
    description: 'Make an entry from the user\'s password manager usable under a secret name (no value is copied or returned). The user must approve in a native dialog. Check tresor_providers for the reference syntax; ask the user for the exact reference rather than guessing.',
    inputSchema: {
      name: z.string().describe('Secret name to use in env/{{secret:NAME}}'),
      provider: z.string().describe('Provider id, e.g. "1password", "bitwarden", "keepassxc", "pass"'),
      ref: z.string().describe('Reference in the provider\'s syntax, e.g. "op://Private/OpenAI/credential"'),
      description: z.string().max(300).optional(),
      hosts: HOSTS,
    },
  }, ({ name, provider, ref, description, hosts }) => guarded(async () => {
    validateName(name);
    const p = getProvider(provider, store.providerContext().config);
    p.validateRef(ref);
    const answer = await dialogs.confirm(
      `Claude wants to use "${ref}" from ${p.label} as secret "${name}".\n\n`
      + 'Claude can then inject the value into commands and requests, but never sees it.'
      + `${hosts?.length ? `\nOnly to: ${hosts.join(', ')}` : ''}\n\nAllow?`,
    );
    if (answer !== 'yes') return `Not linked (${answer === 'timeout' ? 'dialog timed out' : 'user declined'}).`;
    const action = store.link(name, provider, ref, { description, hosts });
    try {
      const value = await store.resolve(name);
      return `Secret "${name}" ${action} → ${p.label}. Test fetch ok (${value.length} chars).`;
    } catch (e) {
      return `Secret "${name}" ${action} → ${p.label}, but the test fetch failed: ${e instanceof Error ? e.message : String(e)}`;
    }
  }));

  server.registerTool('tresor_run', {
    description: `Run a command with secrets injected as environment variables (preferred) or into args. stdout/stderr are returned with every secret value redacted. No shell: for pipes or $VARS use ["sh","-c","..."] (Windows: ["powershell","-Command","..."]). ${PLACEHOLDER_HINT}`,
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
