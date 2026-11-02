/**
 * Secret store: values live in the macOS Keychain (via @napi-rs/keyring, service
 * "tresor", account = secret name). Only non-secret metadata (description, allowed
 * hosts, timestamps) is kept in a small JSON index so listing never touches a value.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { createRequire } from 'module';
import { dirname } from 'path';
import { indexPath } from './paths.js';

export const KEYCHAIN_SERVICE = 'tresor';
const NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;

export interface SecretBackend {
  get(name: string): string | null;
  set(name: string, value: string): void;
  delete(name: string): boolean;
}

export interface SecretMeta {
  description?: string;
  /** If set, http injection only sends this secret to these hostnames. */
  hosts?: string[];
  createdAt: string;
  updatedAt: string;
}

interface IndexFile {
  version: 1;
  secrets: Record<string, SecretMeta>;
}

export class KeychainBackend implements SecretBackend {
  constructor(private readonly service = KEYCHAIN_SERVICE) {}

  // Loaded lazily so unit tests (MemoryBackend) never touch the native binding.
  private entry(name: string) {
    const { Entry } = createRequire(import.meta.url)('@napi-rs/keyring') as typeof import('@napi-rs/keyring');
    return new Entry(this.service, name);
  }

  get(name: string): string | null { return this.entry(name).getPassword() ?? null; }
  set(name: string, value: string): void { this.entry(name).setPassword(value); }
  delete(name: string): boolean { return this.entry(name).deletePassword(); }
}

export class MemoryBackend implements SecretBackend {
  private readonly values = new Map<string, string>();
  get(name: string) { return this.values.get(name) ?? null; }
  set(name: string, value: string) { this.values.set(name, value); }
  delete(name: string) { return this.values.delete(name); }
}

export function validateName(name: string): void {
  if (!NAME_RE.test(name)) {
    throw new Error(`Invalid secret name "${name}". Allowed: letters, digits, "_", "-", "." (max 64).`);
  }
}

export function normalizeHosts(hosts: string[] | undefined): string[] | undefined {
  if (!hosts || hosts.length === 0) return undefined;
  return [...new Set(hosts.map(h => h.trim().toLowerCase()).filter(Boolean))];
}

export class SecretStore {
  constructor(
    private readonly backend: SecretBackend,
    private readonly indexFile: string = indexPath(),
  ) {}

  private readIndex(): IndexFile {
    if (!existsSync(this.indexFile)) return { version: 1, secrets: {} };
    const parsed = JSON.parse(readFileSync(this.indexFile, 'utf-8')) as IndexFile;
    if (parsed.version !== 1 || typeof parsed.secrets !== 'object') {
      throw new Error(`Unsupported index format in ${this.indexFile}`);
    }
    return parsed;
  }

  private writeIndex(index: IndexFile): void {
    mkdirSync(dirname(this.indexFile), { recursive: true, mode: 0o700 });
    const tmp = `${this.indexFile}.tmp`;
    writeFileSync(tmp, JSON.stringify(index, null, 2) + '\n', { mode: 0o600 });
    renameSync(tmp, this.indexFile);
  }

  list(): Array<{ name: string } & SecretMeta> {
    const { secrets } = this.readIndex();
    return Object.entries(secrets)
      .map(([name, meta]) => ({ name, ...meta }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  meta(name: string): SecretMeta | undefined {
    return this.readIndex().secrets[name];
  }

  has(name: string): boolean {
    return this.meta(name) !== undefined;
  }

  set(name: string, value: string, opts: { description?: string; hosts?: string[] } = {}): 'created' | 'updated' {
    validateName(name);
    if (value.length === 0) throw new Error('Refusing to store an empty secret.');
    const index = this.readIndex();
    const prev = index.secrets[name];
    const now = new Date().toISOString();
    this.backend.set(name, value);
    index.secrets = {
      ...index.secrets,
      [name]: {
        description: opts.description ?? prev?.description,
        hosts: normalizeHosts(opts.hosts) ?? prev?.hosts,
        createdAt: prev?.createdAt ?? now,
        updatedAt: now,
      },
    };
    this.writeIndex(index);
    return prev ? 'updated' : 'created';
  }

  /** Resolve a value for injection. Never hand the result to a model. */
  resolve(name: string): string {
    validateName(name);
    if (!this.has(name)) throw new Error(`Unknown secret "${name}". Known: ${this.list().map(s => s.name).join(', ') || '(none)'}`);
    const value = this.backend.get(name);
    if (value === null) throw new Error(`Secret "${name}" is in the index but missing from the Keychain. Re-add it with: tresor set ${name}`);
    return value;
  }

  remove(name: string): boolean {
    validateName(name);
    const index = this.readIndex();
    const existed = name in index.secrets;
    this.backend.delete(name);
    const { [name]: _removed, ...rest } = index.secrets;
    this.writeIndex({ ...index, secrets: rest });
    return existed;
  }
}
