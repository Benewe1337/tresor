/**
 * `tresor doctor`: a health report for your secrets — expired or old tokens,
 * values that went missing, locked password managers, secrets nobody uses, and
 * (optionally) tokens that leaked into Claude/agent transcripts. Each finding says
 * what to do; for well-known services it links the page where the token is rotated.
 * Never prints values.
 */
import { readAudit } from './audit.js';
import { isExpired } from './policy.js';
import { runScan } from './scan.js';
const DAY = 86_400_000;
/** Where to rotate tokens of well-known services, matched on name, hosts and description. */
const ROTATE_URLS = [
    [/github|\bgh\b|ghp_/, 'https://github.com/settings/tokens'],
    [/gitlab/, 'https://gitlab.com/-/user_settings/personal_access_tokens'],
    [/openai/, 'https://platform.openai.com/api-keys'],
    [/anthropic|claude/, 'https://console.anthropic.com/settings/keys'],
    [/stripe/, 'https://dashboard.stripe.com/apikeys'],
    [/vercel/, 'https://vercel.com/account/tokens'],
    [/cloudflare/, 'https://dash.cloudflare.com/profile/api-tokens'],
    [/huggingface|\bhf\b/, 'https://huggingface.co/settings/tokens'],
    [/supabase/, 'https://supabase.com/dashboard/account/tokens'],
    [/sentry/, 'https://sentry.io/settings/account/api/auth-tokens/'],
    [/netlify/, 'https://app.netlify.com/user/applications'],
    [/digitalocean/, 'https://cloud.digitalocean.com/account/api/tokens'],
    [/sendgrid/, 'https://app.sendgrid.com/settings/api_keys'],
    [/slack/, 'https://api.slack.com/apps'],
    [/discord/, 'https://discord.com/developers/applications'],
    [/npm/, 'https://docs.npmjs.com/creating-and-viewing-access-tokens'],
    [/google|gcp|gemini|firebase/, 'https://console.cloud.google.com/apis/credentials'],
    [/aws|amazon/, 'https://console.aws.amazon.com/iam/home#/security_credentials'],
];
export function rotateUrlFor(name, meta) {
    const haystack = [name, ...(meta.hosts ?? []), meta.description ?? ''].join(' ').toLowerCase();
    return ROTATE_URLS.find(([re]) => re.test(haystack))?.[1];
}
const days = (ms) => Math.floor(ms / DAY);
export async function runDoctor(store, opts = {}) {
    const now = opts.now ?? new Date();
    const staleDays = opts.staleDays ?? 180;
    const unusedDays = opts.unusedDays ?? 90;
    const findings = [];
    const secrets = store.list();
    const audit = readAudit({ limit: Number.MAX_SAFE_INTEGER });
    const lastUse = new Map();
    for (const e of audit)
        if (e.ok)
            for (const s of e.secrets)
                lastUse.set(s, Math.max(lastUse.get(s) ?? 0, Date.parse(e.ts)));
    const providerIds = [...new Set(secrets.filter(s => s.source).map(s => s.source.provider))];
    const statuses = providerIds.length ? new Map((await store.providerStatuses()).map(p => [p.id, p])) : new Map();
    for (const s of secrets) {
        const url = rotateUrlFor(s.name, s);
        const where = s.source ? ` in ${statuses.get(s.source.provider)?.label ?? s.source.provider}` : '';
        const expires = s.policy?.expiresAt ? Date.parse(s.policy.expiresAt) : undefined;
        if (isExpired(s.policy?.expiresAt, now)) {
            findings.push({ level: 'error', secret: s.name, message: `expired on ${s.policy.expiresAt.slice(0, 10)}`, action: `rotate it${where}, then \`tresor policy ${s.name} --expires <new date>\``, rotateUrl: url });
        }
        else if (expires && expires - now.getTime() < 14 * DAY) {
            findings.push({ level: 'warn', secret: s.name, message: `expires in ${days(expires - now.getTime())} day(s)`, action: `rotate it${where} soon`, rotateUrl: url });
        }
        if (s.dynamic) {
            // nothing stored that could age; minting problems show up on use
        }
        else if (s.source) {
            const st = statuses.get(s.source.provider);
            if (st && !st.ready)
                findings.push({ level: 'warn', secret: s.name, message: `${st.label} is not ready (${st.detail})`, action: 'unlock / log in to the password manager' });
        }
        else {
            try {
                await store.resolve(s.name);
                const age = now.getTime() - Date.parse(s.updatedAt);
                if (age > staleDays * DAY && !s.policy?.expiresAt) {
                    findings.push({ level: 'warn', secret: s.name, message: `stored ${days(age)} days ago and never replaced`, action: `rotate it and store the new value: tresor set ${s.name}`, rotateUrl: url });
                }
            }
            catch {
                findings.push({ level: 'error', secret: s.name, message: 'listed, but the value is missing from the OS credential store', action: `tresor set ${s.name} (or tresor rm ${s.name})` });
            }
        }
        const since = Math.max(Date.parse(s.createdAt), lastUse.get(s.name) ?? 0);
        if (now.getTime() - since > unusedDays * DAY) {
            findings.push({ level: 'info', secret: s.name, message: lastUse.has(s.name) ? `not used for ${days(now.getTime() - since)} days` : `never used since it was added ${days(now.getTime() - since)} days ago`, action: `if it is not needed any more: revoke it at the service and tresor rm ${s.name}`, rotateUrl: url });
        }
        if (!s.hosts && !s.dynamic && url && /api|key|token/.test(`${s.name} ${s.description ?? ''}`.toLowerCase())) {
            findings.push({ level: 'info', secret: s.name, message: 'not pinned to a host', action: `tresor policy ${s.name} --host <api host> so tresor_http only sends it there` });
        }
    }
    if (opts.transcripts) {
        const report = await runScan(store, { transcripts: true });
        const bySecret = new Map();
        for (const f of report.findings)
            bySecret.set(f.secret, (bySecret.get(f.secret) ?? 0) + 1);
        for (const [name, count] of bySecret) {
            const meta = store.meta(name);
            findings.push({ level: 'error', secret: name, message: `appears ${count}× in agent transcripts – the value has been exposed`, action: `rotate it now${meta?.source ? ` in ${meta.source.provider}` : `, then tresor set ${name}`}`, rotateUrl: meta ? rotateUrlFor(name, meta) : undefined });
        }
    }
    const order = { error: 0, warn: 1, info: 2 };
    return findings.sort((a, b) => order[a.level] - order[b.level] || (a.secret ?? '').localeCompare(b.secret ?? ''));
}
export function formatDoctor(findings, total) {
    if (findings.length === 0)
        return `✓ ${total} secret(s), nothing to do`;
    const icon = { error: '✗', warn: '!', info: '·' };
    const lines = findings.map(f => {
        const head = `${icon[f.level]} ${f.secret ? `${f.secret}: ` : ''}${f.message}`;
        return [head, f.action ? `    → ${f.action}` : '', f.rotateUrl ? `    ↗ ${f.rotateUrl}` : ''].filter(Boolean).join('\n');
    });
    const counts = ['error', 'warn', 'info'].map(l => `${findings.filter(f => f.level === l).length} ${l}`).join(', ');
    return `${lines.join('\n')}\n\n${total} secret(s): ${counts}`;
}
