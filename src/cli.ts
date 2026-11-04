#!/usr/bin/env node
/**
 * tresor CLI — for the human. Values are typed/pasted here (hidden) or taken from
 * the clipboard, never passed as arguments (those end up in shell history / ps).
 */

import spawn from 'cross-spawn';
import { existsSync } from 'fs';
import { resolve as resolvePath } from 'path';
import { appendAudit } from './audit.js';
import { cmdImport, cmdLog, cmdPolicy, cmdProfile, cmdScan } from './cli-tools.js';
import { askYesNo, fail, readHidden, say, takeFlag, takeSwitch } from './cli-util.js';
import { exec } from './platform/exec.js';
import { takeClipboard } from './platform/clipboard.js';
import { isExpired } from './policy.js';
import { describeProfile, findProfile, isTrusted, trustProfile } from './profile.js';
import { bitwardenLock, bitwardenUnlock, BWS_TOKEN_KEY } from './providers/bitwarden.js';
import { loadProvidersConfig, saveProvidersConfig, getProvider } from './providers/index.js';
import { KEEPASS_PASSWORD_KEY } from './providers/keepassxc.js';
import { KeychainBackend, SecretStore } from './store.js';
import { fill, placeholderNames } from './template.js';

const USAGE = `tresor — API tokens from your OS keychain or password manager, for Claude Code

Store locally (macOS Keychain / Windows Credential Manager / Linux Secret Service):
  tresor set <name> [--clip] [-d "description"] [--host api.example.com ...]
        type/paste the value hidden (or pipe it); --clip takes the clipboard and clears it
  tresor import [.env] [--remove] [--all | --only A,B | --except C] [--prefix p] [--yes] [--dry-run]
        move credentials out of a .env into the keychain, write .tresor.json

Link from a password manager (nothing is copied):
  tresor link <name> <provider> <reference> [-d ...] [--host ...]
        e.g. tresor link openai 1password "op://Private/OpenAI/credential"
             tresor link github bitwarden "GitHub PAT#token"
  tresor providers                 installed managers, status and reference syntax
  tresor unlock bitwarden          unlock bw, keep the session in the keychain
  tresor lock bitwarden            drop the session, lock bw
  tresor setup keepassxc --db <file.kdbx> [--keyfile <file>] [--no-password]
  tresor setup bws                 access token for Bitwarden Secrets Manager

Use:
  tresor run [-e VAR=name ...] [--no-profile] -- <cmd> [args]
        start a command with secrets as env vars (stdio passed through, e.g. for MCP servers).
        Without -e the nearest .tresor.json is used. In args: {{secret:name}}
  tresor profile [allow | add VAR=name ... | rm VAR ...]   project mapping (.tresor.json)

Protect:
  tresor scan [paths…] [--staged] [--transcripts] [--local-only]
        find stored secret values in files, staged changes or Claude transcripts (exit 1 on a hit)
  tresor scan --install-hook [--force]   git pre-commit hook running "tresor scan --staged"
  tresor policy <name> [--allow-cmd gh,git] [--confirm always|session|off] [--expires 2027-01-31|off]
                       [--host h] [--clear-hosts] [--clear-allow-cmd]
  tresor log [name] [-n 50]        usage log (no values)

General:
  tresor list                      names + metadata (never values)
  tresor rm <name>                 delete a local secret / remove a link

Claude uses the MCP server (tresor-mcp) and never sees values.`;

async function cmdSet(store: SecretStore, args: string[]) {
  const description = takeFlag(args, '-d')[0];
  const hosts = takeFlag(args, '--host');
  const clip = takeSwitch(args, '--clip');
  const name = args[0] ?? fail('usage: tresor set <name>');
  const value = clip ? await takeClipboard() : await readHidden(`Value for "${name}": `);
  if (!value) fail('empty value, nothing stored');
  const action = store.set(name, value, { description, hosts });
  say(`✓ ${name} ${action === 'created' ? 'stored' : 'updated'} (${value.length} chars)${clip ? ', clipboard cleared' : ''}`);
}

async function cmdLink(store: SecretStore, args: string[]) {
  const description = takeFlag(args, '-d')[0];
  const hosts = takeFlag(args, '--host');
  const [name, provider, ref] = args;
  if (!name || !provider || !ref) fail('usage: tresor link <name> <provider> <reference>');
  const action = store.link(name, provider, ref, { description, hosts });
  const label = getProvider(provider, store.providerContext().config).label;
  try {
    const value = await store.resolve(name);
    say(`✓ ${name} ${action === 'created' ? 'linked' : 'updated'} → ${label} (test fetch ok, ${value.length} chars)`);
  } catch (e) {
    say(`! ${name} linked → ${label}, but the test fetch failed: ${e instanceof Error ? e.message : e}`);
  }
}

function cmdList(store: SecretStore) {
  const items = store.list();
  if (items.length === 0) return say('(no secrets)');
  for (const s of items) {
    const where = s.source ? `[${s.source.provider}] ${s.source.ref}` : '[local]';
    const hosts = s.hosts ? `  → ${s.hosts.join(', ')}` : '';
    const flags = [
      s.policy?.allowCommands ? `cmds: ${s.policy.allowCommands.join(',')}` : '',
      s.policy?.confirm ? `confirm: ${s.policy.confirm}` : '',
      isExpired(s.policy?.expiresAt) ? '⚠ EXPIRED' : s.policy?.expiresAt ? `expires ${s.policy.expiresAt.slice(0, 10)}` : '',
    ].filter(Boolean).join(', ');
    say(`${s.name.padEnd(22)} ${s.updatedAt.slice(0, 10)}  ${where}${s.description ? `  – ${s.description}` : ''}${hosts}${flags ? `  [${flags}]` : ''}`);
  }
}

async function cmdProviders(store: SecretStore) {
  for (const p of await store.providerStatuses()) {
    const mark = p.ready ? '✓' : p.installed ? '…' : '–';
    say(`${mark} ${p.id.padEnd(10)} ${p.label.padEnd(26)} ${p.detail}`);
    if (p.installed) say(`  ${''.padEnd(10)} reference: ${p.refHelp}`);
  }
}

async function cmdSetup(store: SecretStore, args: string[]) {
  const what = args.shift();
  const ctx = store.providerContext();
  if (what === 'bws') {
    const token = await readHidden('BWS access token: ');
    if (!token) fail('empty, nothing stored');
    ctx.internal.set(BWS_TOKEN_KEY, token);
    return say('✓ access token stored in the keychain');
  }
  if (what === 'keepassxc') {
    const db = takeFlag(args, '--db')[0] ?? fail('usage: tresor setup keepassxc --db <file.kdbx>');
    const keyFile = takeFlag(args, '--keyfile')[0];
    const noPassword = takeSwitch(args, '--no-password');
    const database = resolvePath(db);
    if (!existsSync(database)) fail(`database not found: ${database}`);
    const password = noPassword ? null : await readHidden('KeePassXC database password: ');
    const check = await exec('keepassxc-cli', ['ls', '-q', ...(keyFile ? ['-k', resolvePath(keyFile)] : []), ...(noPassword ? ['--no-password'] : []), database], {
      input: password === null ? undefined : `${password}\n`,
    }).catch(e => fail(`cannot run keepassxc-cli: ${e.message}`));
    if (check.code !== 0) fail(`unlock failed: ${check.stderr.trim()}`);
    if (password !== null) ctx.internal.set(KEEPASS_PASSWORD_KEY, password);
    saveProvidersConfig({ ...loadProvidersConfig(), keepassxc: { database, keyFile: keyFile && resolvePath(keyFile), noPassword: noPassword || undefined } });
    return say(`✓ KeePassXC set up: ${database}`);
  }
  fail('usage: tresor setup keepassxc --db <file.kdbx> | tresor setup bws');
}

/** Profile env for `tresor run` without -e: asks once per profile content in a terminal. */
async function profileMappings(): Promise<Array<[string, string]>> {
  const profile = findProfile();
  if (!profile) return [];
  if (!isTrusted(profile)) {
    say(`${profile.path} wants to inject:\n${describeProfile(profile)}`);
    if (!(await askYesNo('Trust this profile (until it changes)?'))) fail('profile not trusted – run "tresor profile allow" or pass -e / --no-profile');
    trustProfile(profile);
  }
  return Object.entries(profile.env);
}

async function cmdRun(store: SecretStore, args: string[]) {
  const sep = args.indexOf('--');
  if (sep === -1 || sep === args.length - 1) fail('usage: tresor run [-e VAR=name] [--no-profile] -- <cmd> [args]');
  const opts = args.slice(0, sep);
  const command = args.slice(sep + 1);
  const noProfile = takeSwitch(opts, '--no-profile');
  const explicit = takeFlag(opts, '-e').map(m => {
    const eq = m.indexOf('=');
    if (eq <= 0) fail(`bad mapping "${m}", expected VAR=name`);
    return [m.slice(0, eq), m.slice(eq + 1)] as [string, string];
  });
  // Explicit -e (e.g. in an MCP server config) never pulls in a project profile implicitly.
  const mappings = explicit.length || noProfile ? explicit : await profileMappings();
  const names = [...mappings.map(([, n]) => n), ...placeholderNames(...command)];
  const values = await store.resolveMany(names);
  if (names.length) appendAudit({ via: 'cli', action: 'run', secrets: [...new Set(names)], detail: command.join(' ').slice(0, 200), ok: true });
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const [envVar, name] of mappings) env[envVar] = values[name];
  const [cmd, ...rest] = command.map(a => fill(a, values));
  const child = spawn(cmd, rest, { env, stdio: 'inherit' });
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) process.on(sig, () => child.kill(sig));
  child.on('error', e => fail(e.message));
  child.on('exit', (code, signal) => {
    if (signal && process.platform !== 'win32') process.kill(process.pid, signal);
    else process.exit(code ?? 1);
  });
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  const store = new SecretStore(new KeychainBackend());
  switch (cmd) {
    case 'set': return cmdSet(store, args);
    case 'import': return cmdImport(store, args);
    case 'link': return cmdLink(store, args);
    case 'list': case 'ls': return cmdList(store);
    case 'providers': return cmdProviders(store);
    case 'setup': return cmdSetup(store, args);
    case 'unlock':
      if (args[0] !== 'bitwarden') fail('usage: tresor unlock bitwarden');
      await bitwardenUnlock(store.providerContext());
      return say('✓ Bitwarden unlocked, session kept in the keychain');
    case 'lock':
      if (args[0] !== 'bitwarden') fail('usage: tresor lock bitwarden');
      await bitwardenLock(store.providerContext());
      return say('✓ Bitwarden locked, session removed');
    case 'rm': case 'delete': {
      const name = args[0] ?? fail('usage: tresor rm <name>');
      return say(store.remove(name) ? `✓ ${name} removed` : `${name} did not exist`);
    }
    case 'run': return cmdRun(store, args);
    case 'profile': return cmdProfile(args);
    case 'scan': return cmdScan(store, args);
    case 'policy': return cmdPolicy(store, args);
    case 'log': return cmdLog(args);
    case undefined: case 'help': case '-h': case '--help': return say(USAGE);
    default: fail(`unknown command "${cmd}"\n\n${USAGE}`);
  }
}

main().catch(e => fail(e instanceof Error ? e.message : String(e)));
