#!/usr/bin/env node
/**
 * tresor CLI — for the human. Values are typed/pasted here (hidden) or taken from
 * the clipboard, never passed as arguments (those end up in shell history / ps).
 */

import { execFileSync, spawn } from 'child_process';
import { createInterface } from 'readline';
import { KeychainBackend, SecretStore } from './store.js';
import { fill, placeholderNames } from './template.js';

const USAGE = `tresor — lokale API-Tokens im macOS-Schlüsselbund

  tresor set <name> [--clip] [-d "Beschreibung"] [--host api.example.com ...]
        Wert verdeckt eingeben (oder per Pipe), --clip nimmt die Zwischenablage und leert sie danach
  tresor list                      Namen + Metadaten (nie Werte)
  tresor rm <name>                 Secret löschen
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
    if (i + 1 >= args.length) fail(`${flag} needs a value`);
    values.push(args[i + 1]);
    args.splice(i, 2);
  }
  return values;
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

async function cmdSet(store: SecretStore, args: string[]) {
  const description = takeFlag(args, '-d')[0];
  const hosts = takeFlag(args, '--host');
  const clip = args.includes('--clip');
  const name = args.filter(a => a !== '--clip')[0] ?? fail('usage: tresor set <name>');
  let value: string;
  if (clip) {
    value = execFileSync('pbpaste', { encoding: 'utf-8' }).trim();
    execFileSync('pbcopy', { input: '' });
  } else {
    value = await readHidden(`Wert für "${name}": `);
  }
  if (!value) fail('leerer Wert, nichts gespeichert');
  const action = store.set(name, value, { description, hosts });
  process.stdout.write(`✓ ${name} ${action === 'created' ? 'gespeichert' : 'aktualisiert'} (${value.length} Zeichen)${clip ? ', Zwischenablage geleert' : ''}\n`);
}

function cmdList(store: SecretStore) {
  const items = store.list();
  if (items.length === 0) return process.stdout.write('(keine Secrets)\n');
  for (const s of items) {
    const hosts = s.hosts ? `  → ${s.hosts.join(', ')}` : '';
    process.stdout.write(`${s.name.padEnd(24)} ${s.updatedAt.slice(0, 10)}  ${s.description ?? ''}${hosts}\n`);
  }
}

function cmdRun(store: SecretStore, args: string[]) {
  const sep = args.indexOf('--');
  if (sep === -1 || sep === args.length - 1) fail('usage: tresor run -e VAR=name -- <cmd> [args]');
  const opts = args.slice(0, sep);
  const command = args.slice(sep + 1);
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const mapping of takeFlag(opts, '-e')) {
    const eq = mapping.indexOf('=');
    if (eq <= 0) fail(`bad mapping "${mapping}", expected VAR=name`);
    env[mapping.slice(0, eq)] = store.resolve(mapping.slice(eq + 1));
  }
  const values = Object.fromEntries(placeholderNames(...command).map(n => [n, store.resolve(n)]));
  const [cmd, ...rest] = command.map(a => fill(a, values));
  const child = spawn(cmd, rest, { env, stdio: 'inherit' });
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) process.on(sig, () => child.kill(sig));
  child.on('error', e => fail(e.message));
  child.on('exit', (code, signal) => (signal ? process.kill(process.pid, signal) : process.exit(code ?? 0)));
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  const store = new SecretStore(new KeychainBackend());
  switch (cmd) {
    case 'set': return cmdSet(store, args);
    case 'list': case 'ls': return cmdList(store);
    case 'rm': case 'delete': {
      const name = args[0] ?? fail('usage: tresor rm <name>');
      return process.stdout.write(store.remove(name) ? `✓ ${name} gelöscht\n` : `${name} war nicht vorhanden\n`);
    }
    case 'run': return cmdRun(store, args);
    case undefined: case 'help': case '-h': case '--help': return process.stdout.write(USAGE + '\n');
    default: fail(`unbekannter Befehl "${cmd}"\n\n${USAGE}`);
  }
}

main().catch(e => fail(e instanceof Error ? e.message : String(e)));
