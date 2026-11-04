/**
 * Per-secret policies and the hooks that enforce them around every injection.
 * Policies are set by the human (`tresor policy`); the agent can read them via
 * tresor_list but cannot change them.
 */
import { basename } from 'path';
import { appendAudit } from './audit.js';
export function programName(cmd) {
    return basename(cmd).toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, '');
}
export function isExpired(expiresAt, now = new Date()) {
    return Boolean(expiresAt) && new Date(expiresAt).getTime() < now.getTime();
}
/** Hooks for the MCP server: enforce policies, ask for confirmation, write the audit log. */
export function mcpHooks(store, confirm) {
    const approvedThisSession = new Set();
    return {
        async before(names, usage) {
            const warnings = [];
            for (const name of [...new Set(names)]) {
                const policy = store.meta(name)?.policy;
                if (!policy)
                    continue;
                if (policy.allowCommands?.length) {
                    if (usage.action === 'write_file') {
                        throw new Error(`Secret "${name}" is restricted to ${policy.allowCommands.join(', ')} and may not be written to files.`);
                    }
                    if (usage.action === 'run' && !policy.allowCommands.includes(usage.program ?? '')) {
                        throw new Error(`Secret "${name}" may only be used with: ${policy.allowCommands.join(', ')} (not "${usage.program}").`);
                    }
                }
                if (isExpired(policy.expiresAt)) {
                    warnings.push(`Secret "${name}" expired on ${policy.expiresAt.slice(0, 10)} – ask the user to rotate it.`);
                }
                const needsConfirm = policy.confirm === 'always' || (policy.confirm === 'session' && !approvedThisSession.has(name));
                if (needsConfirm) {
                    const answer = await confirm(`Claude wants to use secret "${name}" for:\n\n${usage.action}: ${usage.detail}\n\nAllow?`);
                    if (answer !== 'yes')
                        throw new Error(`User did not allow using "${name}" (${answer === 'timeout' ? 'dialog timed out' : 'declined'}).`);
                    approvedThisSession.add(name);
                }
            }
            return warnings;
        },
        after(names, usage, error) {
            appendAudit({
                via: 'mcp', action: usage.action, secrets: [...new Set(names)], detail: usage.detail,
                ok: !error, error: error ? (error instanceof Error ? error.message : String(error)).slice(0, 200) : undefined,
            });
        },
    };
}
/** No enforcement (tests, human CLI paths that log separately). */
export const NO_HOOKS = { before: async () => [], after: () => { } };
