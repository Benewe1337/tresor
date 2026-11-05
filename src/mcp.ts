/**
 * tresor MCP server. Deliberately has NO tool that returns a secret value, no
 * delete tool and no way to change policies — those are human-only CLI actions.
 * Linking a password-manager entry or trusting a project profile always needs the
 * user's OK in a native dialog.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { appendAudit, readAudit } from './audit.js';
import { runDoctor } from './doctor.js';
import { runImport } from './import.js';
import { httpWithSecrets, runWithSecrets, writeFileWithSecrets } from './inject.js';
import { confirm, promptSecret } from './platform/prompt.js';
import { mcpHooks } from './policy.js';
import { describeProfile, findProfile, isTrusted, trustProfile } from './profile.js';
import { getProvider } from './providers/index.js';
import { runScan } from './scan.js';
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
- Use tokens only through tresor_run (env vars, or bundles for multi-value credentials like AWS; a project's .tresor.json is applied automatically), tresor_http ({{secret:NAME}} placeholders) or tresor_write_file. Output comes back with values replaced by [tresor:NAME].
- Before committing, run tresor_scan with staged=true. Plaintext .env files can be moved into tresor with tresor_import.
- Never try to read values another way (keychain CLIs, password-manager CLIs, printing env vars, reading files tresor wrote); a guard hook blocks this and it defeats the purpose.
- Errors like "Bitwarden is locked", "not set up" or policy refusals need the user: tell them what to do, do not work around them.`;

const PLACEHOLDER_HINT = 'Reference secrets as {{secret:NAME}}.';
const HOSTS = z.array(z.string()).optional().describe('Restrict http injection to these hostnames, e.g. ["api.openai.com"]');

export function createServer(store: SecretStore, dialogs: Dialogs = { promptSecret, confirm }): McpServer {
  const server = new McpServer({ name: 'tresor', version: '0.5.0' }, { instructions: SERVER_INSTRUCTIONS });
  const hooks = mcpHooks(store, dialogs.confirm);

  /** Env mappings from the nearest .tresor.json, after the user trusted that exact content. */
  async function profileEnv(cwd: string | undefined): Promise<{ env: Record<string, string>; bundles: string[]; path?: string }> {
    const profile = findProfile(cwd ?? process.cwd());
    if (!profile || (Object.keys(profile.env).length === 0 && profile.bundles.length === 0)) return { env: {}, bundles: [] };
    if (!isTrusted(profile)) {
      const answer = await dialogs.confirm(`The project profile\n${profile.path}\nwants to inject these secrets into commands Claude runs there:\n\n${describeProfile(profile)}\n\nAllow (until the file changes)?`);
      if (answer !== 'yes') throw new Error(`Project profile ${profile.path} not trusted (${answer === 'timeout' ? 'dialog timed out' : 'user declined'}). Pass useProfile=false to run without it.`);
      trustProfile(profile);
    }
    return { env: profile.env, bundles: profile.bundles, path: profile.path };
  }

  server.registerTool('tresor_list', {
    description: 'List secrets: names, descriptions, allowed hosts, policies, for linked ones the password manager + reference, for dynamic (short-lived) ones the generator type. Never returns values. Dynamic bundles (e.g. aws-sso) are used via tresor_run bundles.',
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
    appendAudit({ via: 'mcp', action: 'request', secrets: [name], detail: action, ok: true });
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
    appendAudit({ via: 'mcp', action: 'link', secrets: [name], detail: `${provider} ${ref}`, ok: true });
    try {
      const value = await store.resolve(name);
      return `Secret "${name}" ${action} → ${p.label}. Test fetch ok (${value.length} chars).`;
    } catch (e) {
      return `Secret "${name}" ${action} → ${p.label}, but the test fetch failed: ${e instanceof Error ? e.message : String(e)}`;
    }
  }));

  server.registerTool('tresor_run', {
    description: `Run a command with secrets injected as environment variables (preferred) or into args. Mappings from the nearest .tresor.json are added automatically (the user approves a profile once). stdout/stderr are returned with every secret value redacted. No shell: for pipes or $VARS use ["sh","-c","..."] (Windows: ["powershell","-Command","..."]). ${PLACEHOLDER_HINT}`,
    inputSchema: {
      command: z.array(z.string()).min(1).describe('argv, e.g. ["gh","api","user"]'),
      env: z.record(z.string(), z.string()).optional().describe('ENV_VAR → secret name, e.g. {"GH_TOKEN":"github"}; overrides the project profile'),
      bundles: z.array(z.string()).optional().describe('Multi-value dynamic secrets that set their own env vars, e.g. ["aws-dev"] → AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN'),
      cwd: z.string().optional(),
      useProfile: z.boolean().optional().describe('Apply .tresor.json from cwd upwards (default true)'),
      timeoutMs: z.number().int().positive().max(600_000).optional(),
    },
  }, ({ useProfile = true, ...input }) => guarded(async () => {
    const profile = useProfile ? await profileEnv(input.cwd) : { env: {}, bundles: [] as string[] };
    const env = { ...profile.env, ...input.env };
    const bundles = [...new Set([...profile.bundles, ...(input.bundles ?? [])])];
    const result = await runWithSecrets(store, { ...input, env, bundles }, hooks);
    return { ...result, injected: Object.keys(env), ...(bundles.length ? { bundles } : {}), ...(profile.path ? { profile: profile.path } : {}) };
  }));

  server.registerTool('tresor_http', {
    description: `HTTPS request with secrets substituted into url/headers/body. Response is redacted; redirects are not followed. ${PLACEHOLDER_HINT} Example header: {"Authorization":"Bearer {{secret:openai}}"}`,
    inputSchema: {
      url: z.string(),
      method: z.string().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      body: z.string().optional(),
      timeoutMs: z.number().int().positive().max(600_000).optional(),
    },
  }, input => guarded(() => httpWithSecrets(store, input, hooks)));

  server.registerTool('tresor_write_file', {
    description: `Write a file (mode 600) with secrets filled in, e.g. a .env. The file is registered so you cannot read it back. Make sure it is gitignored. ${PLACEHOLDER_HINT}`,
    inputSchema: {
      path: z.string(),
      content: z.string().describe('e.g. "OPENAI_API_KEY={{secret:openai}}\\n"'),
    },
  }, ({ path, content }) => guarded(() => writeFileWithSecrets(store, path, content, hooks)));

  server.registerTool('tresor_scan', {
    description: 'Check whether any stored secret value (also base64/URL/JSON-encoded) appears in files, in the staged git changes, or in Claude Code transcripts. Reports secret name, file and line — never the value. Run with staged=true before every commit.',
    inputSchema: {
      paths: z.array(z.string()).optional().describe('Files or directories to scan (node_modules/.git skipped)'),
      staged: z.boolean().optional().describe('Scan what would be committed (git index)'),
      transcripts: z.boolean().optional().describe('Scan Claude Code session transcripts (~/.claude/projects)'),
      cwd: z.string().optional(),
    },
  }, input => guarded(async () => {
    if (!input.paths?.length && !input.staged && !input.transcripts) throw new Error('Nothing to scan: pass paths, staged=true or transcripts=true.');
    const report = await runScan(store, input);
    appendAudit({ via: 'mcp', action: 'scan', secrets: report.secretsChecked, detail: `${report.findings.length} finding(s) in ${report.scannedFiles} files`, ok: true });
    return {
      ...report,
      verdict: report.findings.length ? 'LEAK FOUND – remove the values; if they were committed, pushed or shared, the user must rotate them' : 'clean',
    };
  }));

  server.registerTool('tresor_import', {
    description: 'Move credentials from a plaintext .env file into tresor (OS keychain) and record the mapping in .tresor.json next to it. By default only entries that look like credentials are imported; values are never returned. With remove=true the imported lines are deleted from the .env after a verified read-back.',
    inputSchema: {
      path: z.string().describe('Path to the .env file'),
      prefix: z.string().optional().describe('Prefix for secret names, e.g. the project name'),
      only: z.array(z.string()).optional().describe('Import exactly these keys'),
      except: z.array(z.string()).optional(),
      remove: z.boolean().optional(),
    },
  }, ({ path, prefix, only, except, remove }) => guarded(async () => {
    const result = await runImport(store, path, { prefix, only, except, remove });
    if (result.imported.length) {
      appendAudit({ via: 'mcp', action: 'import', secrets: result.imported.map(i => i.name), detail: path, ok: true });
    }
    return { ...result, profile: result.profile?.path ?? null };
  }));

  server.registerTool('tresor_doctor', {
    description: 'Health check of all secrets: expired or old tokens, values missing from the keychain, locked password managers, unused secrets, missing host pins, and (transcripts=true) tokens that leaked into agent transcripts. Each finding has an action and, for known services, the URL where the token is rotated. Never returns values.',
    inputSchema: {
      transcripts: z.boolean().optional().describe('Also scan agent transcripts for leaked values (slower)'),
    },
  }, ({ transcripts }) => guarded(() => runDoctor(store, { transcripts })));

  server.registerTool('tresor_log', {
    description: 'Show the usage log: which secret was used when, for which command/host/file, and whether it was allowed. Never contains values.',
    inputSchema: {
      secret: z.string().optional(),
      limit: z.number().int().positive().max(500).optional(),
    },
  }, ({ secret, limit }) => guarded(() => readAudit({ secret, limit })));

  return server;
}

export async function main(): Promise<void> {
  const server = createServer(new SecretStore(new KeychainBackend()));
  await server.connect(new StdioServerTransport());
}
