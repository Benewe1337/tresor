import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { dirname } from 'path';
import { providersConfigPath } from '../paths.js';
import { bitwarden, bitwardenSecretsManager } from './bitwarden.js';
import { customProvider, gopass, lastpass, pass } from './cli-managers.js';
import { keepassxc } from './keepassxc.js';
import { onePassword } from './onepassword.js';
import { ProviderError, type Provider, type ProvidersConfig } from './types.js';

export * from './types.js';

export const BUILTIN_PROVIDERS: readonly Provider[] = [onePassword, bitwarden, bitwardenSecretsManager, keepassxc, pass, gopass, lastpass];

export function loadProvidersConfig(path = providersConfigPath()): ProvidersConfig {
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, 'utf-8')) as ProvidersConfig;
}

export function saveProvidersConfig(config: ProvidersConfig, path = providersConfigPath()): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(`${path}.tmp`, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  renameSync(`${path}.tmp`, path);
}

export function allProviders(config: ProvidersConfig): Provider[] {
  const builtinIds = new Set(BUILTIN_PROVIDERS.map(p => p.id));
  const custom = Object.entries(config.custom ?? {}).map(([id, cfg]) => {
    if (builtinIds.has(id) || id === 'local') throw new ProviderError(`Custom provider "${id}" collides with a built-in provider.`);
    return customProvider(id, cfg);
  });
  return [...BUILTIN_PROVIDERS, ...custom];
}

export function getProvider(id: string, config: ProvidersConfig): Provider {
  const p = allProviders(config).find(x => x.id === id);
  if (!p) throw new ProviderError(`Unknown provider "${id}". Available: ${allProviders(config).map(x => x.id).join(', ')}`);
  return p;
}
