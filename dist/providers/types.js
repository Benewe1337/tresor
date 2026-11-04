/**
 * A provider resolves a reference (e.g. `op://Private/OpenAI/credential`) to a
 * secret value by calling the password manager's own CLI. Providers never store
 * values; tresor only remembers *which* reference a secret name points to.
 */
export class ProviderError extends Error {
}
