#!/usr/bin/env node
/**
 * tresor CLI — for the human. Values are typed/pasted here (hidden) or taken from
 * the clipboard, never passed as arguments (those end up in shell history / ps).
 */

import spawn from 'cross-spawn';
import { existsSync } from 'fs';
import { resolve as resolvePath } from 'path';
import { createInterface } from 'readline';
import { exec } from './platform/exec.js';
import { takeClipboard } from './platform/clipboard.js';
import { bitwardenLock, bitwardenUnlock, BWS_TOKEN_KEY } from './providers/bitwarden.js';
import { loadProvidersConfig, saveProvidersConfig, getProvider } from './providers/index.js';
import { KEEPASS_PASSWORD_KEY } from './providers/keepassxc.js';
import { KeychainBackend, SecretStore } from './store.js';
import { fill, placeholderNames } from './template.js';

const USAGE = `tresor — API-Tokens lokal im System-Schlüsselbund oder aus deinem Passwort-Manager

Lokal speichern (macOS-Schlüsselbund / Windows-Anmeldeinformationen / Linux Secret Service):
  tresor set <name> [--clip] [-d "Beschreibung"] [--host api.example.com ...]
        Wert verdeckt eingeben (oder per Pipe); --clip nimmt die Zwischenablage und leert sie

Aus einem Passwort-Manager verknüpfen (es wird nichts kopiert):
  tresor link <name> <provider> <referenz> [-d ...] [--host ...]
        z.B. tresor link openai 1password "op://Private/OpenAI/credential"
             tresor link github bitwarden "GitHub PAT#token"
  tresor providers                 installierte Manager, Status und Referenz-Syntax
  tresor unlock bitwarden          bw entsperren, Session im Schlüsselbund ablegen
  tresor lock bitwarden            Session löschen, bw sperren
  tresor setup keepassxc --db <datei.kdbx> [--keyfile <datei>] [--no-password]
  tresor setup bws                 Access-Token für Bitwarden Secrets Manager

Allgemein:
  tresor list                      Namen + Metadaten (nie Werte)
  tresor rm <name>                 lokales Secret löschen bzw. Verknüpfung entfernen
  tresor run -e VAR=name [...] -- <cmd> [args]
        Befehl mit Secrets als Env-Variablen starten (stdio durchgereicht, z.B. für MCP-Server).
        In Args: {{secret:name}}

Claude nutzt den MCP-Server (tresor-mcp) und bekommt nie Werte zu sehen.`;

function fail(msg: string): never {
  process.stderr.write(`tresor: ${msg}\n`);
  process.exit(1);
}

function takeFlag(args: string[], flag: string): string[] {
  const values: string[] = [];
  for (let i = args.indexOf(flag); i !== -1; i = args.indexOf(flag)) {
    if (i + 1 >= args.length) fail(`${flag} braucht einen Wert`);
    values.push(args[i + 1]);
    args.splice(i, 2);
  }
  return values;
}

function takeSwitch(args: string[], flag: string): boolean {
  const i = args.indexOf(flag);
  if (i === -1) return false;
  args.splice(i, 1);
  return true;
}

async function readHidden(question: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString('utf-8').trim();
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  // Suppress echo of typed characters.
  (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = (s: string) => {
    if (s.includes(question)) process.stdout.write(s);
  };
  const answer = await new Promise<string>(res => rl.question(question, res));
  rl.close();
  process.stdout.write('\n');
  return answer.trim();
}

const say = (s: string) => process.stdout.write(`${s}\n`);

async function cmdSet(store: SecretStore, args: string[]) {
  const description = takeFlag(args, '-d')[0];
  const hosts = takeFlag(args, '--host');
  const clip = takeSwitch(args, '--clip');
  const name = args[0] ?? fail('usage: tresor set <name>');
  const value = clip ? await takeClipboard() : await readHidden(`Wert für "${name}": `);
  if (!value) fail('leerer Wert, nichts gespeichert');
  const action = store.set(name, value, { description, hosts });
  say(`✓ ${name} ${action === 'created' ? 'gespeichert' : 'aktualisiert'} (${value.length} Zeichen)${clip ? ', Zwischenablage geleert' : ''}`);
}

async function cmdLink(store: SecretStore, args: string[]) {
  const description = takeFlag(args, '-d')[0];
  const hosts = takeFlag(args, '--host');
  const [name, provider, ref] = args;
  if (!name || !provider || !ref) fail('usage: tresor link <name> <provider> <referenz>');
  const action = store.link(name, provider, ref, { description, hosts });
  const label = getProvider(provider, store.providerContext().config).label;
  try {
    const value = await store.resolve(name);
    say(`✓ ${name} ${action === 'created' ? 'verknüpft' : 'aktualisiert'} → ${label} (Test-Abruf ok, ${value.length} Zeichen)`);
  } catch (e) {
    say(`! ${name} verknüpft → ${label}, aber Test-Abruf fehlgeschlagen: ${e instanceof Error ? e.message : e}`);
  }
}

function cmdList(store: SecretStore) {
  const items = store.list();
  if (items.length === 0) return say('(keine Secrets)');
  for (const s of items) {
    const where = s.source ? `[${s.source.provider}] ${s.source.ref}` : '[lokal]';
    const hosts = s.hosts ? `  → ${s.hosts.join(', ')}` : '';
    say(`${s.name.padEnd(22)} ${s.updatedAt.slice(0, 10)}  ${where}${s.description ? `  – ${s.description}` : ''}${hosts}`);
  }
}

async function cmdProviders(store: SecretStore) {
  for (const p of await store.providerStatuses()) {
    const mark = p.ready ? '✓' : p.installed ? '…' : '–';
    say(`${mark} ${p.id.padEnd(10)} ${p.label.padEnd(26)} ${p.detail}`);
    if (p.installed) say(`  ${''.padEnd(10)} Referenz: ${p.refHelp}`);
  }
}

async function cmdSetup(store: SecretStore, args: string[]) {
  const what = args.shift();
  const ctx = store.providerContext();
  if (what === 'bws') {
    const token = await readHidden('BWS Access-Token: ');
    if (!token) fail('leer, nichts gespeichert');
    ctx.internal.set(BWS_TOKEN_KEY, token);
    return say('✓ Access-Token im Schlüsselbund gespeichert');
  }
  if (what === 'keepassxc') {
    const db = takeFlag(args, '--db')[0] ?? fail('usage: tresor setup keepassxc --db <datei.kdbx>');
    const keyFile = takeFlag(args, '--keyfile')[0];
    const noPassword = takeSwitch(args, '--no-password');
    const database = resolvePath(db);
    if (!existsSync(database)) fail(`Datenbank nicht gefunden: ${database}`);
    const password = noPassword ? null : await readHidden('KeePassXC-Datenbankpasswort: ');
    const check = await exec('keepassxc-cli', ['ls', '-q', ...(keyFile ? ['-k', resolvePath(keyFile)] : []), ...(noPassword ? ['--no-password'] : []), database], {
      input: password === null ? undefined : `${password}\n`,
    }).catch(e => fail(`keepassxc-cli nicht ausführbar: ${e.message}`));
    if (check.code !== 0) fail(`Entsperren fehlgeschlagen: ${check.stderr.trim()}`);
    if (password !== null) ctx.internal.set(KEEPASS_PASSWORD_KEY, password);
    saveProvidersConfig({ ...loadProvidersConfig(), keepassxc: { database, keyFile: keyFile && resolvePath(keyFile), noPassword: noPassword || undefined } });
    return say(`✓ KeePassXC eingerichtet: ${database}`);
  }
  fail('usage: tresor setup keepassxc --db <datei> | tresor setup bws');
}

async function cmdRun(store: SecretStore, args: string[]) {
  const sep = args.indexOf('--');
  if (sep === -1 || sep === args.length - 1) fail('usage: tresor run -e VAR=name -- <cmd> [args]');
  const opts = args.slice(0, sep);
  const command = args.slice(sep + 1);
  const mappings = takeFlag(opts, '-e').map(m => {
    const eq = m.indexOf('=');
    if (eq <= 0) fail(`bad mapping "${m}", expected VAR=name`);
    return [m.slice(0, eq), m.slice(eq + 1)] as const;
  });
  const values = await store.resolveMany([...mappings.map(([, n]) => n), ...placeholderNames(...command)]);
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
    case 'link': return cmdLink(store, args);
    case 'list': case 'ls': return cmdList(store);
    case 'providers': return cmdProviders(store);
    case 'setup': return cmdSetup(store, args);
    case 'unlock':
      if (args[0] !== 'bitwarden') fail('usage: tresor unlock bitwarden');
      await bitwardenUnlock(store.providerContext());
      return say('✓ Bitwarden entsperrt, Session im Schlüsselbund');
    case 'lock':
      if (args[0] !== 'bitwarden') fail('usage: tresor lock bitwarden');
      await bitwardenLock(store.providerContext());
      return say('✓ Bitwarden gesperrt, Session gelöscht');
    case 'rm': case 'delete': {
      const name = args[0] ?? fail('usage: tresor rm <name>');
      return say(store.remove(name) ? `✓ ${name} entfernt` : `${name} war nicht vorhanden`);
    }
    case 'run': return cmdRun(store, args);
    case undefined: case 'help': case '-h': case '--help': return say(USAGE);
    default: fail(`unbekannter Befehl "${cmd}"\n\n${USAGE}`);
  }
}

main().catch(e => fail(e instanceof Error ? e.message : String(e)));
