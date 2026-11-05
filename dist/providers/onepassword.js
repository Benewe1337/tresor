import { exec, onPath } from '../platform/exec.js';
import { notInstalled, requireNonEmpty, runCli } from './common.js';
import { ProviderError } from './types.js';
const OP_REF = /^op:\/\/[^/]+\/[^/]+\/.+/;
export const onePassword = {
    id: '1password',
    label: '1Password',
    refHelp: 'op://<vault>/<item>/<field>  (in 1Password: field → "Copy Secret Reference")',
    validateRef(ref) {
        if (!OP_REF.test(ref))
            throw new ProviderError(`1Password reference must look like: ${this.refHelp}`);
    },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        return requireNonEmpty(this.label, ref, await runCli(this.label, 'op', ['read', '--no-newline', ref], { env: ctx.env }));
    },
    async status(ctx) {
        if (!onPath('op', ctx.env))
            return notInstalled('op');
        if (ctx.env.OP_SERVICE_ACCOUNT_TOKEN)
            return { installed: true, ready: true, detail: 'service account token set' };
        const r = await exec('op', ['whoami'], { env: ctx.env, timeoutMs: 10_000 });
        return r.code === 0
            ? { installed: true, ready: true, detail: 'signed in' }
            : { installed: true, ready: false, detail: 'not signed in – enable the desktop app integration or run `op signin`' };
    },
};
