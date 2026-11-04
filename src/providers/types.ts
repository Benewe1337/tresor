/**
 * A provider resolves a reference (e.g. `op://Private/OpenAI/credential`) to a
 * secret value by calling the password manager's own CLI. Providers never store
 * values; tresor only remembers *which* reference a secret name points to.
 */

export interface ProviderContext {
  /** Provider-internal credentials kept in the OS keychain (session keys, DB passwords). */
  internal: {
    get(key: string): string | null;
    set(key: string, value: string): void;
    delete(key: string): boolean;
  };
  config: ProvidersConfig;
  /** Base environment for spawned CLIs (overridable in tests). */
  env: NodeJS.ProcessEnv;
}

export interface ProviderStatus {
  installed: boolean;
  ready: boolean;
  detail: string;
}

export interface Provider {
  id: string;
  label: string;
  /** Short reference syntax help shown to users and to Claude. */
  refHelp: string;
  validateRef(ref: string): void;
  resolve(ref: string, ctx: ProviderContext): Promise<string>;
  status(ctx: ProviderContext): Promise<ProviderStatus>;
}

export interface CustomProviderConfig {
  label?: string;
  /** argv with `{ref}` placeholder, e.g. ["lpass","show","--password","{ref}"] */
  command: string[];
  /** Optional: JSON path (dot-separated) to pick from JSON stdout, e.g. "value" */
  jsonPath?: string;
}

export interface ProvidersConfig {
  keepassxc?: { database: string; keyFile?: string; noPassword?: boolean };
  custom?: Record<string, CustomProviderConfig>;
}

export class ProviderError extends Error {}
