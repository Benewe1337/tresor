/** Password managers whose CLI just prints a value: pass, gopass, LastPass, and user-defined ones. */
import { onPath } from '../platform/exec.js';
import { notInstalled, pickJson, requireNonEmpty, runCli, splitField } from './common.js';
import { ProviderError } from './types.js';
function nonEmptyPath(label, help) {
    return (ref) => {
        if (!splitField(ref).path.trim())
            throw new ProviderError(`${label} reference: ${help}`);
    };
}
const installedOnly = (bin) => async (ctx) => onPath(bin, ctx.env) ? { installed: true, ready: true, detail: 'installed' } : notInstalled(bin);
export const pass = {
    id: 'pass',
    label: 'pass',
    refHelp: '<path/in/store>[#field]  (no #: first line; #user: the "user: …" line)',
    validateRef(ref) { nonEmptyPath(this.label, this.refHelp)(ref); },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        const { path, field } = splitField(ref);
        const lines = (await runCli(this.label, 'pass', ['show', path], { env: ctx.env })).split(/\r?\n/);
        if (!field)
            return requireNonEmpty(this.label, ref, lines[0] ?? '');
        const prefix = `${field.toLowerCase()}:`;
        const line = lines.slice(1).find(l => l.toLowerCase().startsWith(prefix));
        if (line === undefined)
            throw new ProviderError(`pass: no field "${field}" in "${path}".`);
        return requireNonEmpty(this.label, ref, line.slice(prefix.length).trim());
    },
    status: installedOnly('pass'),
};
export const gopass = {
    id: 'gopass',
    label: 'gopass',
    refHelp: '<path/in/store>[#key]  (no #: password)',
    validateRef(ref) { nonEmptyPath(this.label, this.refHelp)(ref); },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        const { path, field } = splitField(ref);
        const args = field ? ['show', path, field] : ['show', '-o', path];
        return requireNonEmpty(this.label, ref, await runCli(this.label, 'gopass', args, { env: ctx.env }));
    },
    status: installedOnly('gopass'),
};
const LPASS_FLAGS = { password: '--password', username: '--username', notes: '--notes', url: '--url' };
export const lastpass = {
    id: 'lastpass',
    label: 'LastPass',
    refHelp: '<name or id>[#password|username|notes|url|<custom field>]',
    validateRef(ref) { nonEmptyPath(this.label, this.refHelp)(ref); },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        const { path, field = 'password' } = splitField(ref);
        const flag = LPASS_FLAGS[field.toLowerCase()] ?? `--field=${field}`;
        return requireNonEmpty(this.label, ref, await runCli(this.label, 'lpass', ['show', flag, path], { env: ctx.env }));
    },
    status: installedOnly('lpass'),
};
/** User-defined provider from providers.json, e.g. Doppler, Infisical, HashiCorp Vault, Dashlane. */
export function customProvider(id, cfg) {
    if (!Array.isArray(cfg.command) || cfg.command.length === 0 || !cfg.command.some(a => a.includes('{ref}'))) {
        throw new ProviderError(`Custom provider "${id}": "command" must be an argv array containing {ref}.`);
    }
    const [bin, ...args] = cfg.command;
    const label = cfg.label ?? id;
    return {
        id,
        label,
        refHelp: `Substituted for {ref} in ${JSON.stringify(cfg.command)}`,
        validateRef(ref) {
            if (!ref.trim())
                throw new ProviderError(`${label}: empty reference.`);
        },
        async resolve(ref, ctx) {
            this.validateRef(ref);
            const out = await runCli(label, bin, args.map(a => a.split('{ref}').join(ref)), { env: ctx.env });
            if (!cfg.jsonPath)
                return requireNonEmpty(label, ref, out);
            const v = pickJson(JSON.parse(out), cfg.jsonPath);
            return requireNonEmpty(label, ref, typeof v === 'string' ? v : '');
        },
        status: installedOnly(bin),
    };
}
