/**
 * Secret store. A secret name is either
 *   - local:  value lives in the OS credential store (macOS Keychain, Windows
 *             Credential Manager, Linux Secret Service) via @napi-rs/keyring, or
 *   - linked: a reference into a password manager (1Password, Bitwarden, …),
 *             resolved on every use through that manager's CLI.
 * Only non-secret metadata lives in index.json, so listing never touches a value.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { createRequire } from 'module';
import { dirname } from 'path';
import { indexPath } from './paths.js';
import { getProvider, loadProvidersConfig, allProviders } from './providers/index.js';
export const KEYCHAIN_SERVICE = 'tresor';
const NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const INTERNAL_PREFIX = '__internal.';
export class KeychainBackend {
    service;
    constructor(service = KEYCHAIN_SERVICE) {
        this.service = service;
    }
    // Loaded lazily so unit tests (MemoryBackend) never touch the native binding.
    entry(name) {
        const { Entry } = createRequire(import.meta.url)('@napi-rs/keyring');
        // Linux: pin to Secret Service. The library's fallback, the kernel keyring,
        // forgets everything on reboot — silently losing tokens is worse than an error.
        const store = process.env.TRESOR_LINUX_STORE ?? 'secret-service';
        return new Entry(this.service, name, { linux: { store } });
    }
    get(name) { return this.wrap(() => this.entry(name).getPassword() ?? null); }
    set(name, value) { this.wrap(() => this.entry(name).setPassword(value)); }
    delete(name) { return this.wrap(() => this.entry(name).deletePassword()); }
    wrap(fn) {
        try {
            return fn();
        }
        catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            const hint = process.platform === 'linux'
                ? ' – Is a Secret Service (gnome-keyring, KWallet, KeePassXC) running and unlocked? Headless fallback: TRESOR_LINUX_STORE=keyutils (lost on reboot).'
                : process.platform === 'win32' && /long/i.test(msg) ? ' – Windows Credential Manager holds at most 2560 bytes per value.' : '';
            throw new Error(`Credential store: ${msg}${hint}`);
        }
    }
}
export class MemoryBackend {
    values = new Map();
    get(name) { return this.values.get(name) ?? null; }
    set(name, value) { this.values.set(name, value); }
    delete(name) { return this.values.delete(name); }
}
export function validateName(name) {
    if (!NAME_RE.test(name) || name.startsWith('__')) {
        throw new Error(`Invalid secret name "${name}". Allowed: letters, digits, "_", "-", "." (max 64, not starting with "__").`);
    }
}
export function normalizeHosts(hosts) {
    if (!hosts || hosts.length === 0)
        return undefined;
    return [...new Set(hosts.map(h => h.trim().toLowerCase()).filter(Boolean))];
}
export class SecretStore {
    backend;
    opts;
    indexFile;
    constructor(backend, opts = {}) {
        this.backend = backend;
        this.opts = opts;
        this.indexFile = opts.indexFile ?? indexPath();
    }
    readIndex() {
        if (!existsSync(this.indexFile))
            return { version: 1, secrets: {} };
        const parsed = JSON.parse(readFileSync(this.indexFile, 'utf-8'));
        if (parsed.version !== 1 || typeof parsed.secrets !== 'object') {
            throw new Error(`Unsupported index format in ${this.indexFile}`);
        }
        return parsed;
    }
    writeIndex(index) {
        mkdirSync(dirname(this.indexFile), { recursive: true, mode: 0o700 });
        const tmp = `${this.indexFile}.tmp`;
        writeFileSync(tmp, JSON.stringify(index, null, 2) + '\n', { mode: 0o600 });
        renameSync(tmp, this.indexFile);
    }
    upsert(name, patch) {
        const index = this.readIndex();
        const prev = index.secrets[name];
        const now = new Date().toISOString();
        const next = {
            description: patch.description ?? prev?.description,
            hosts: normalizeHosts(patch.hosts) ?? prev?.hosts,
            source: 'source' in patch ? patch.source : prev?.source,
            policy: 'policy' in patch ? patch.policy : prev?.policy,
            createdAt: prev?.createdAt ?? now,
            updatedAt: now,
        };
        this.writeIndex({ ...index, secrets: { ...index.secrets, [name]: next } });
        return prev ? 'updated' : 'created';
    }
    /** Human-only (CLI): change hosts / policy of an existing secret. */
    updatePolicy(name, patch) {
        validateName(name);
        const prev = this.meta(name);
        if (!prev)
            throw new Error(`Unknown secret "${name}"`);
        const policy = { ...prev.policy, ...patch.policy };
        const cleaned = Object.fromEntries(Object.entries(policy).filter(([, v]) => v !== undefined && !(Array.isArray(v) && v.length === 0)));
        const index = this.readIndex();
        const next = {
            ...prev,
            hosts: patch.hosts === null ? undefined : normalizeHosts(patch.hosts) ?? prev.hosts,
            policy: Object.keys(cleaned).length ? cleaned : undefined,
            updatedAt: new Date().toISOString(),
        };
        this.writeIndex({ ...index, secrets: { ...index.secrets, [name]: next } });
        return next;
    }
    providerContext() {
        const b = this.backend;
        return {
            internal: {
                get: key => b.get(INTERNAL_PREFIX + key),
                set: (key, value) => b.set(INTERNAL_PREFIX + key, value),
                delete: key => b.delete(INTERNAL_PREFIX + key),
            },
            config: this.opts.providersConfig ?? loadProvidersConfig(),
            env: this.opts.env ?? process.env,
        };
    }
    list() {
        const { secrets } = this.readIndex();
        return Object.entries(secrets)
            .map(([name, meta]) => ({ name, ...meta }))
            .sort((a, b) => a.name.localeCompare(b.name));
    }
    meta(name) {
        return this.readIndex().secrets[name];
    }
    has(name) {
        return this.meta(name) !== undefined;
    }
    set(name, value, opts = {}) {
        validateName(name);
        if (value.length === 0)
            throw new Error('Refusing to store an empty secret.');
        const src = this.meta(name)?.source;
        if (src)
            throw new Error(`"${name}" is linked to ${src.provider}. Run \`tresor rm ${name}\` first.`);
        this.backend.set(name, value);
        return this.upsert(name, opts);
    }
    /** Point a secret name at a password-manager reference. Stores no value. */
    link(name, provider, ref, opts = {}) {
        validateName(name);
        const prev = this.meta(name);
        if (prev && !prev.source)
            throw new Error(`"${name}" is stored locally. Run \`tresor rm ${name}\` before linking it.`);
        getProvider(provider, this.providerContext().config).validateRef(ref);
        return this.upsert(name, { ...opts, source: { provider, ref } });
    }
    /** Resolve a value for injection. Never hand the result to a model. */
    async resolve(name) {
        validateName(name);
        const meta = this.meta(name);
        if (!meta)
            throw new Error(`Unknown secret "${name}". Known: ${this.list().map(s => s.name).join(', ') || '(none)'}`);
        if (meta.source) {
            const ctx = this.providerContext();
            return getProvider(meta.source.provider, ctx.config).resolve(meta.source.ref, ctx);
        }
        const value = this.backend.get(name);
        if (value === null)
            throw new Error(`Secret "${name}" is in the index but missing from the credential store. Re-add it with: tresor set ${name}`);
        return value;
    }
    async resolveMany(names) {
        const unique = [...new Set(names)];
        // Sequential on purpose: password-manager CLIs (bw, op) dislike parallel calls.
        const out = {};
        for (const n of unique)
            out[n] = await this.resolve(n);
        return out;
    }
    remove(name) {
        validateName(name);
        const index = this.readIndex();
        const meta = index.secrets[name];
        if (!meta?.source)
            this.backend.delete(name);
        const { [name]: _removed, ...rest } = index.secrets;
        this.writeIndex({ ...index, secrets: rest });
        return meta !== undefined;
    }
    async providerStatuses() {
        const ctx = this.providerContext();
        return Promise.all(allProviders(ctx.config).map(async (p) => {
            try {
                return { id: p.id, label: p.label, refHelp: p.refHelp, ...(await p.status(ctx)) };
            }
            catch (e) {
                return { id: p.id, label: p.label, refHelp: p.refHelp, installed: false, ready: false, detail: e instanceof Error ? e.message : String(e) };
            }
        }));
    }
}
