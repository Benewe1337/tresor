import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { dirname } from 'path';
import { providersConfigPath } from '../paths.js';
import { bitwarden, bitwardenSecretsManager } from './bitwarden.js';
import { customProvider, gopass, lastpass, pass } from './cli-managers.js';
import { keepassxc } from './keepassxc.js';
import { onePassword } from './onepassword.js';
import { ProviderError } from './types.js';
export * from './types.js';
export const BUILTIN_PROVIDERS = [onePassword, bitwarden, bitwardenSecretsManager, keepassxc, pass, gopass, lastpass];
export function loadProvidersConfig(path = providersConfigPath()) {
    if (!existsSync(path))
        return {};
    return JSON.parse(readFileSync(path, 'utf-8'));
}
export function saveProvidersConfig(config, path = providersConfigPath()) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(`${path}.tmp`, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
    renameSync(`${path}.tmp`, path);
}
export function allProviders(config) {
    const builtinIds = new Set(BUILTIN_PROVIDERS.map(p => p.id));
    const custom = Object.entries(config.custom ?? {}).map(([id, cfg]) => {
        if (builtinIds.has(id) || id === 'local')
            throw new ProviderError(`Custom provider "${id}" collides with a built-in provider.`);
        return customProvider(id, cfg);
    });
    return [...BUILTIN_PROVIDERS, ...custom];
}
export function getProvider(id, config) {
    const p = allProviders(config).find(x => x.id === id);
    if (!p)
        throw new ProviderError(`Unknown provider "${id}". Available: ${allProviders(config).map(x => x.id).join(', ')}`);
    return p;
}
