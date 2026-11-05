/**
 * Proton Pass, Dashlane and Keeper. Command lines follow the vendors' docs/source
 * (researched 2026-11); all run without a TTY, so a CLI that would prompt for a
 * login hits the exec timeout instead of hanging.
 */
import { exec, onPath } from '../platform/exec.js';
import { notInstalled, requireNonEmpty, runCli, splitField } from './common.js';
import { ProviderError } from './types.js';
const STATUS_TIMEOUT = 10_000;
async function statusByExit(bin, args, ctx, okDetail, failDetail) {
    if (!onPath(bin, ctx.env))
        return notInstalled(bin);
    const r = await exec(bin, args, { env: ctx.env, timeoutMs: STATUS_TIMEOUT }).catch(() => null);
    return r?.code === 0 ? { installed: true, ready: true, detail: okDetail } : { installed: true, ready: false, detail: failDetail };
}
export const protonPass = {
    id: 'protonpass',
    label: 'Proton Pass',
    refHelp: 'pass://<vault>/<item>/<field>  (field: password, username, email, totp or a custom field; ids or names)',
    validateRef(ref) {
        if (!/^pass:\/\/[^/]+\/[^/]+\/.+/.test(ref))
            throw new ProviderError(`Proton Pass reference: ${this.refHelp}`);
    },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        return requireNonEmpty(this.label, ref, await runCli(this.label, 'pass-cli', ['item', 'view', ref], { env: ctx.env }));
    },
    status: ctx => statusByExit('pass-cli', ['info'], ctx, 'logged in', 'not logged in – run `pass-cli login` (PAT sessions expire after 2 h)'),
};
export const dashlane = {
    id: 'dashlane',
    label: 'Dashlane',
    refHelp: 'dl://<item id>/<field>  (e.g. dl://abcd-1234/password; use the id, titles are ambiguous)',
    validateRef(ref) {
        if (!/^dl:\/\/[^/]+\/.+/.test(ref))
            throw new ProviderError(`Dashlane reference: ${this.refHelp}`);
    },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        return requireNonEmpty(this.label, ref, await runCli(this.label, 'dcli', ['read', ref], { env: ctx.env }));
    },
    async status(ctx) {
        if (!onPath('dcli', ctx.env))
            return notInstalled('dcli');
        if (ctx.env.DASHLANE_SERVICE_DEVICE_KEYS)
            return { installed: true, ready: true, detail: 'service device keys set' };
        // `dcli status` always exits 0; parse its text.
        const r = await exec('dcli', ['status'], { env: ctx.env, timeoutMs: STATUS_TIMEOUT }).catch(() => null);
        const out = r?.stdout ?? '';
        const ready = /Logged in:\s*Yes/i.test(out) && !/Locked:\s*Yes/i.test(out);
        return { installed: true, ready, detail: ready ? 'logged in, unlocked' : 'not logged in or locked – run `dcli sync` in a terminal' };
    },
};
const KEEPER_FLAGS = { password: [], username: ['--login'], login: ['--login'], totp: ['--totp'] };
export const keeper = {
    id: 'keeper',
    label: 'Keeper',
    refHelp: '<record UID or path>[#password|username|totp|notes|<field label>]',
    validateRef(ref) {
        if (!splitField(ref).path.trim())
            throw new ProviderError(`Keeper reference: ${this.refHelp}`);
    },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        const { path, field = 'password' } = splitField(ref);
        const flags = KEEPER_FLAGS[field.toLowerCase()] ?? ['--field', field];
        const out = await runCli(this.label, 'keeper', ['--batch-mode', 'clipboard-copy', '--output', 'stdout', ...flags, path], { env: ctx.env });
        if (!out)
            throw new ProviderError(`Keeper: field "${field}" of "${path}" is empty or missing.`);
        return out;
    },
    async status(ctx) {
        if (!onPath('keeper', ctx.env))
            return notInstalled('keeper');
        const r = await exec('keeper', ['login-status'], { env: ctx.env, timeoutMs: STATUS_TIMEOUT }).catch(() => null);
        const ready = Boolean(r && /Logged in/i.test(r.stdout) && !/Not logged in/i.test(r.stdout));
        return { installed: true, ready, detail: ready ? 'logged in' : 'not logged in – enable persistent login (keeper this-device persistent-login on)' };
    },
};
