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
const USAGE = `tresor — API tokens from your OS keychain or password manager, for Claude Code

Store locally (macOS Keychain / Windows Credential Manager / Linux Secret Service):
  tresor set <name> [--clip] [-d "description"] [--host api.example.com ...]
        type/paste the value hidden (or pipe it); --clip takes the clipboard and clears it

Link from a password manager (nothing is copied):
  tresor link <name> <provider> <reference> [-d ...] [--host ...]
        e.g. tresor link openai 1password "op://Private/OpenAI/credential"
             tresor link github bitwarden "GitHub PAT#token"
  tresor providers                 installed managers, status and reference syntax
  tresor unlock bitwarden          unlock bw, keep the session in the keychain
  tresor lock bitwarden            drop the session, lock bw
  tresor setup keepassxc --db <file.kdbx> [--keyfile <file>] [--no-password]
  tresor setup bws                 access token for Bitwarden Secrets Manager

General:
  tresor list                      names + metadata (never values)
  tresor rm <name>                 delete a local secret / remove a link
  tresor run -e VAR=name [...] -- <cmd> [args]
        start a command with secrets as env vars (stdio passed through, e.g. for MCP servers).
        In args: {{secret:name}}

Claude uses the MCP server (tresor-mcp) and never sees values.`;
function fail(msg) {
    process.stderr.write(`tresor: ${msg}\n`);
    process.exit(1);
}
function takeFlag(args, flag) {
    const values = [];
    for (let i = args.indexOf(flag); i !== -1; i = args.indexOf(flag)) {
        if (i + 1 >= args.length)
            fail(`${flag} needs a value`);
        values.push(args[i + 1]);
        args.splice(i, 2);
    }
    return values;
}
function takeSwitch(args, flag) {
    const i = args.indexOf(flag);
    if (i === -1)
        return false;
    args.splice(i, 1);
    return true;
}
async function readHidden(question) {
    if (!process.stdin.isTTY) {
        const chunks = [];
        for await (const c of process.stdin)
            chunks.push(c);
        return Buffer.concat(chunks).toString('utf-8').trim();
    }
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    // Suppress echo of typed characters.
    rl._writeToOutput = (s) => {
        if (s.includes(question))
            process.stdout.write(s);
    };
    const answer = await new Promise(res => rl.question(question, res));
    rl.close();
    process.stdout.write('\n');
    return answer.trim();
}
const say = (s) => process.stdout.write(`${s}\n`);
async function cmdSet(store, args) {
    const description = takeFlag(args, '-d')[0];
    const hosts = takeFlag(args, '--host');
    const clip = takeSwitch(args, '--clip');
    const name = args[0] ?? fail('usage: tresor set <name>');
    const value = clip ? await takeClipboard() : await readHidden(`Value for "${name}": `);
    if (!value)
        fail('empty value, nothing stored');
    const action = store.set(name, value, { description, hosts });
    say(`✓ ${name} ${action === 'created' ? 'stored' : 'updated'} (${value.length} chars)${clip ? ', clipboard cleared' : ''}`);
}
async function cmdLink(store, args) {
    const description = takeFlag(args, '-d')[0];
    const hosts = takeFlag(args, '--host');
    const [name, provider, ref] = args;
    if (!name || !provider || !ref)
        fail('usage: tresor link <name> <provider> <reference>');
    const action = store.link(name, provider, ref, { description, hosts });
    const label = getProvider(provider, store.providerContext().config).label;
    try {
        const value = await store.resolve(name);
        say(`✓ ${name} ${action === 'created' ? 'linked' : 'updated'} → ${label} (test fetch ok, ${value.length} chars)`);
    }
    catch (e) {
        say(`! ${name} linked → ${label}, but the test fetch failed: ${e instanceof Error ? e.message : e}`);
    }
}
function cmdList(store) {
    const items = store.list();
    if (items.length === 0)
        return say('(no secrets)');
    for (const s of items) {
        const where = s.source ? `[${s.source.provider}] ${s.source.ref}` : '[local]';
        const hosts = s.hosts ? `  → ${s.hosts.join(', ')}` : '';
        say(`${s.name.padEnd(22)} ${s.updatedAt.slice(0, 10)}  ${where}${s.description ? `  – ${s.description}` : ''}${hosts}`);
    }
}
async function cmdProviders(store) {
    for (const p of await store.providerStatuses()) {
        const mark = p.ready ? '✓' : p.installed ? '…' : '–';
        say(`${mark} ${p.id.padEnd(10)} ${p.label.padEnd(26)} ${p.detail}`);
        if (p.installed)
            say(`  ${''.padEnd(10)} reference: ${p.refHelp}`);
    }
}
async function cmdSetup(store, args) {
    const what = args.shift();
    const ctx = store.providerContext();
    if (what === 'bws') {
        const token = await readHidden('BWS access token: ');
        if (!token)
            fail('empty, nothing stored');
        ctx.internal.set(BWS_TOKEN_KEY, token);
        return say('✓ access token stored in the keychain');
    }
    if (what === 'keepassxc') {
        const db = takeFlag(args, '--db')[0] ?? fail('usage: tresor setup keepassxc --db <file.kdbx>');
        const keyFile = takeFlag(args, '--keyfile')[0];
        const noPassword = takeSwitch(args, '--no-password');
        const database = resolvePath(db);
        if (!existsSync(database))
            fail(`database not found: ${database}`);
        const password = noPassword ? null : await readHidden('KeePassXC database password: ');
        const check = await exec('keepassxc-cli', ['ls', '-q', ...(keyFile ? ['-k', resolvePath(keyFile)] : []), ...(noPassword ? ['--no-password'] : []), database], {
            input: password === null ? undefined : `${password}\n`,
        }).catch(e => fail(`cannot run keepassxc-cli: ${e.message}`));
        if (check.code !== 0)
            fail(`unlock failed: ${check.stderr.trim()}`);
        if (password !== null)
            ctx.internal.set(KEEPASS_PASSWORD_KEY, password);
        saveProvidersConfig({ ...loadProvidersConfig(), keepassxc: { database, keyFile: keyFile && resolvePath(keyFile), noPassword: noPassword || undefined } });
        return say(`✓ KeePassXC set up: ${database}`);
    }
    fail('usage: tresor setup keepassxc --db <file.kdbx> | tresor setup bws');
}
async function cmdRun(store, args) {
    const sep = args.indexOf('--');
    if (sep === -1 || sep === args.length - 1)
        fail('usage: tresor run -e VAR=name -- <cmd> [args]');
    const opts = args.slice(0, sep);
    const command = args.slice(sep + 1);
    const mappings = takeFlag(opts, '-e').map(m => {
        const eq = m.indexOf('=');
        if (eq <= 0)
            fail(`bad mapping "${m}", expected VAR=name`);
        return [m.slice(0, eq), m.slice(eq + 1)];
    });
    const values = await store.resolveMany([...mappings.map(([, n]) => n), ...placeholderNames(...command)]);
    const env = { ...process.env };
    for (const [envVar, name] of mappings)
        env[envVar] = values[name];
    const [cmd, ...rest] = command.map(a => fill(a, values));
    const child = spawn(cmd, rest, { env, stdio: 'inherit' });
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'])
        process.on(sig, () => child.kill(sig));
    child.on('error', e => fail(e.message));
    child.on('exit', (code, signal) => {
        if (signal && process.platform !== 'win32')
            process.kill(process.pid, signal);
        else
            process.exit(code ?? 1);
    });
}
async function main() {
    const [cmd, ...args] = process.argv.slice(2);
    const store = new SecretStore(new KeychainBackend());
    switch (cmd) {
        case 'set': return cmdSet(store, args);
        case 'link': return cmdLink(store, args);
        case 'list':
        case 'ls': return cmdList(store);
        case 'providers': return cmdProviders(store);
        case 'setup': return cmdSetup(store, args);
        case 'unlock':
            if (args[0] !== 'bitwarden')
                fail('usage: tresor unlock bitwarden');
            await bitwardenUnlock(store.providerContext());
            return say('✓ Bitwarden unlocked, session kept in the keychain');
        case 'lock':
            if (args[0] !== 'bitwarden')
                fail('usage: tresor lock bitwarden');
            await bitwardenLock(store.providerContext());
            return say('✓ Bitwarden locked, session removed');
        case 'rm':
        case 'delete': {
            const name = args[0] ?? fail('usage: tresor rm <name>');
            return say(store.remove(name) ? `✓ ${name} removed` : `${name} did not exist`);
        }
        case 'run': return cmdRun(store, args);
        case undefined:
        case 'help':
        case '-h':
        case '--help': return say(USAGE);
        default: fail(`unknown command "${cmd}"\n\n${USAGE}`);
    }
}
main().catch(e => fail(e instanceof Error ? e.message : String(e)));
