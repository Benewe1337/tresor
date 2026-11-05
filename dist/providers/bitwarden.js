/**
 * Bitwarden / Vaultwarden via `bw`, and Bitwarden Secrets Manager via `bws`.
 *
 * bw needs an unlocked session. `tresor unlock bitwarden` runs `bw unlock --raw`
 * in the user's terminal and keeps the session key in the OS keychain, so the MCP
 * server (which has no terminal) can use it until `tresor lock bitwarden`.
 */
import spawn from 'cross-spawn';
import { exec, onPath } from '../platform/exec.js';
import { notInstalled, pickJson, requireNonEmpty, runCli, splitField } from './common.js';
import { ProviderError } from './types.js';
export const BW_SESSION_KEY = 'bitwarden.session';
export const BWS_TOKEN_KEY = 'bws.token';
function bwEnv(ctx) {
    const session = ctx.internal.get(BW_SESSION_KEY) ?? ctx.env.BW_SESSION;
    return session ? { ...ctx.env, BW_SESSION: session } : { ...ctx.env };
}
function pickField(item, field) {
    switch (field.toLowerCase()) {
        case 'password': return item.login?.password;
        case 'username': return item.login?.username;
        case 'notes': return item.notes;
        case 'uri':
        case 'url': return item.login?.uris?.[0]?.uri;
        default: return item.fields?.find(f => f.name === field)?.value;
    }
}
export const bitwarden = {
    id: 'bitwarden',
    label: 'Bitwarden',
    refHelp: '<item id or exact name>[#password|username|notes|totp|uri|<custom field>]  (default: password)',
    validateRef(ref) {
        if (!splitField(ref).path.trim())
            throw new ProviderError(`Bitwarden reference: ${this.refHelp}`);
    },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        const { path, field = 'password' } = splitField(ref);
        const env = bwEnv(ctx);
        if (!env.BW_SESSION)
            throw new ProviderError('Bitwarden is locked. In your terminal: tresor unlock bitwarden');
        const item = JSON.parse(await runCli(this.label, 'bw', ['get', 'item', path, '--nointeraction'], { env }));
        // bw get does a search; insist on an exact hit so a substring can't pick another item.
        if (item.id !== path && item.name !== path) {
            throw new ProviderError(`Bitwarden: no exact match for "${path}" (found: "${item.name}"). Use the item id.`);
        }
        if (field.toLowerCase() === 'totp') {
            return requireNonEmpty(this.label, ref, await runCli(this.label, 'bw', ['get', 'totp', item.id, '--nointeraction'], { env }));
        }
        const value = pickField(item, field);
        if (value === undefined)
            throw new ProviderError(`Bitwarden: item "${item.name}" has no field "${field}".`);
        return requireNonEmpty(this.label, ref, value ?? '');
    },
    async status(ctx) {
        if (!onPath('bw', ctx.env))
            return notInstalled('bw');
        const r = await exec('bw', ['status', '--nointeraction'], { env: bwEnv(ctx), timeoutMs: 10_000 });
        let state = 'unknown';
        try {
            state = String(JSON.parse(r.stdout).status ?? state);
        }
        catch { /* keep default */ }
        const ready = state === 'unlocked';
        const hint = state === 'unauthenticated' ? ' – run `bw login`, then tresor unlock bitwarden'
            : state === 'locked' ? ' – run tresor unlock bitwarden' : '';
        return { installed: true, ready, detail: `${state}${hint}` };
    },
};
/** Interactive: `bw unlock --raw` in the user's terminal, session key → OS keychain. */
export function bitwardenUnlock(ctx) {
    return new Promise((resolve, reject) => {
        const child = spawn('bw', ['unlock', '--raw'], { env: ctx.env, stdio: ['inherit', 'pipe', 'inherit'] });
        let out = '';
        child.stdout?.on('data', (d) => { out += d.toString('utf-8'); });
        child.on('error', reject);
        child.on('close', code => {
            const session = out.trim();
            if (code !== 0 || !session)
                return reject(new ProviderError('bw unlock failed.'));
            ctx.internal.set(BW_SESSION_KEY, session);
            resolve();
        });
    });
}
export async function bitwardenLock(ctx) {
    ctx.internal.delete(BW_SESSION_KEY);
    if (onPath('bw', ctx.env))
        await exec('bw', ['lock', '--nointeraction'], { env: ctx.env, timeoutMs: 20_000 });
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const bitwardenSecretsManager = {
    id: 'bws',
    label: 'Bitwarden Secrets Manager',
    refHelp: '<secret id (UUID)>',
    validateRef(ref) {
        if (!UUID.test(ref))
            throw new ProviderError(`Bitwarden Secrets Manager reference: ${this.refHelp}`);
    },
    async resolve(ref, ctx) {
        this.validateRef(ref);
        const token = ctx.internal.get(BWS_TOKEN_KEY) ?? ctx.env.BWS_ACCESS_TOKEN;
        if (!token)
            throw new ProviderError('No access token. In your terminal: tresor setup bws');
        const json = JSON.parse(await runCli(this.label, 'bws', ['secret', 'get', ref, '--output', 'json'], {
            env: { ...ctx.env, BWS_ACCESS_TOKEN: token },
        }));
        const value = pickJson(json, 'value');
        return requireNonEmpty(this.label, ref, typeof value === 'string' ? value : '');
    },
    async status(ctx) {
        if (!onPath('bws', ctx.env))
            return notInstalled('bws');
        const hasToken = Boolean(ctx.internal.get(BWS_TOKEN_KEY) ?? ctx.env.BWS_ACCESS_TOKEN);
        return { installed: true, ready: hasToken, detail: hasToken ? 'access token present' : 'no access token – run tresor setup bws' };
    },
};
