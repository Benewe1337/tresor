/**
 * Injection operations used by the MCP server. Every result that goes back to the
 * caller is passed through the Redactor first; secret values never leave here.
 * Policies, confirmations and the audit log plug in via InjectHooks.
 */
import spawn from 'cross-spawn';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { writtenFilesPath } from './paths.js';
import { NO_HOOKS, programName } from './policy.js';
import { Redactor, truncate } from './redact.js';
import { fill, placeholderNames } from './template.js';
export const DEFAULT_TIMEOUT_MS = 120_000;
export const MAX_OUTPUT_CHARS = 40_000;
const MAX_CAPTURE_BYTES = 10 * 1024 * 1024;
/** Runs `fn` between the before/after hooks so every use is checked and logged exactly once. */
async function guarded(hooks, names, usage, fn) {
    let warnings;
    try {
        warnings = await hooks.before(names, usage);
    }
    catch (e) {
        hooks.after(names, usage, e);
        throw e;
    }
    try {
        const result = await fn();
        hooks.after(names, usage);
        return warnings.length ? { ...result, warnings } : result;
    }
    catch (e) {
        hooks.after(names, usage, e);
        throw e;
    }
}
export async function runWithSecrets(store, input, hooks = NO_HOOKS) {
    if (input.command.length === 0)
        throw new Error('command must not be empty');
    const envMap = input.env ?? {};
    const bundles = [...new Set(input.bundles ?? [])];
    const singles = [...Object.values(envMap), ...placeholderNames(...input.command)];
    const usage = {
        action: 'run',
        program: programName(input.command[0]),
        detail: `${input.command.join(' ').slice(0, 200)}${input.cwd ? `  (in ${input.cwd})` : ''}`,
    };
    return guarded(hooks, [...singles, ...bundles], usage, async () => {
        const values = await store.resolveMany(singles);
        const childEnv = { ...process.env };
        const redactable = { ...values };
        for (const b of bundles) {
            for (const [envVar, v] of Object.entries(await store.resolveBundle(b))) {
                childEnv[envVar] = v;
                redactable[`${b}.${envVar}`] = v;
            }
        }
        const redactor = new Redactor(redactable);
        for (const [envVar, name] of Object.entries(envMap))
            childEnv[envVar] = values[name];
        const [cmd, ...args] = input.command.map(a => fill(a, values));
        return new Promise((res, rej) => {
            const proc = spawn(cmd, args, {
                env: childEnv,
                cwd: input.cwd ?? process.cwd(),
                stdio: ['ignore', 'pipe', 'pipe'],
                windowsHide: true,
            });
            const chunks = { stdout: [], stderr: [] };
            let captured = 0;
            const collect = (key) => (d) => {
                if (captured >= MAX_CAPTURE_BYTES)
                    return;
                captured += d.length;
                chunks[key].push(d);
            };
            proc.stdout?.on('data', collect('stdout'));
            proc.stderr?.on('data', collect('stderr'));
            let timedOut = false;
            const timer = setTimeout(() => { timedOut = true; proc.kill('SIGTERM'); }, input.timeoutMs ?? DEFAULT_TIMEOUT_MS);
            proc.on('error', err => { clearTimeout(timer); rej(new Error(redactor.redact(err.message))); });
            proc.on('close', (code, signal) => {
                clearTimeout(timer);
                const out = (key) => truncate(redactor.redact(Buffer.concat(chunks[key]).toString('utf-8')), MAX_OUTPUT_CHARS);
                res({ exitCode: code, signal, timedOut, stdout: out('stdout'), stderr: out('stderr') });
            });
        });
    });
}
/** Throws if a secret is pinned to hosts and the request goes elsewhere. */
export function assertHostAllowed(store, names, url) {
    for (const name of names) {
        const hosts = store.meta(name)?.hosts;
        if (hosts && !hosts.includes(url.hostname.toLowerCase())) {
            throw new Error(`Secret "${name}" may only be sent to: ${hosts.join(', ')} (request goes to ${url.hostname}).`);
        }
    }
}
export async function httpWithSecrets(store, input, hooks = NO_HOOKS) {
    const headerEntries = Object.entries(input.headers ?? {});
    const names = placeholderNames(input.url, input.body, ...headerEntries.map(([, v]) => v));
    if (names.length === 0)
        throw new Error('No {{secret:NAME}} placeholder found in url, headers or body.');
    // Host shown in the confirmation/audit is taken from the URL *template*, before any secret is filled in.
    let host = '?';
    try {
        host = new URL(input.url.replace(/\{\{secret:[^}]+\}\}/g, 'x')).host;
    }
    catch { /* reported below */ }
    const usage = { action: 'http', detail: `${input.method ?? 'GET'} ${host}` };
    return guarded(hooks, names, usage, async () => {
        const values = await store.resolveMany(names);
        const redactor = new Redactor(values);
        const url = new URL(fill(input.url, values));
        if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '::1'].includes(url.hostname)) {
            throw new Error('Secrets are only sent over https (or to localhost).');
        }
        assertHostAllowed(store, names, url);
        try {
            const response = await fetch(url, {
                method: input.method ?? 'GET',
                headers: Object.fromEntries(headerEntries.map(([k, v]) => [k, fill(v, values)])),
                body: input.body === undefined ? undefined : fill(input.body, values),
                // Never forward secrets to wherever a redirect points.
                redirect: 'manual',
                signal: AbortSignal.timeout(input.timeoutMs ?? DEFAULT_TIMEOUT_MS),
            });
            const headers = {};
            response.headers.forEach((v, k) => { headers[k] = redactor.redact(v); });
            const body = truncate(redactor.redact(await response.text()), MAX_OUTPUT_CHARS);
            return { status: response.status, statusText: response.statusText, headers, body };
        }
        catch (err) {
            throw new Error(redactor.redact(err instanceof Error ? err.message : String(err)));
        }
    });
}
function registerWrittenFile(path) {
    const registry = writtenFilesPath();
    mkdirSync(dirname(registry), { recursive: true, mode: 0o700 });
    const known = existsSync(registry) ? readFileSync(registry, 'utf-8').split('\n') : [];
    if (!known.includes(path))
        appendFileSync(registry, `${path}\n`, { mode: 0o600 });
}
export async function writeFileWithSecrets(store, path, content, hooks = NO_HOOKS) {
    const names = placeholderNames(content);
    if (names.length === 0)
        throw new Error('No {{secret:NAME}} placeholder found in content.');
    const abs = resolve(path);
    return guarded(hooks, names, { action: 'write_file', detail: abs }, async () => {
        const values = await store.resolveMany(names);
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, fill(content, values), { mode: 0o600 });
        registerWrittenFile(abs);
        return { path: abs, secrets: names };
    });
}
