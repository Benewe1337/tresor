/** CLI commands for scanning, importing, project profiles, the usage log and policies. */
import { AGENTS, detectAgents, installAgent, uninstallAgent } from './agents/install.js';
import { formatAudit, readAudit } from './audit.js';
import { askYesNo, fail, say, takeFlag, takeList, takeSwitch } from './cli-util.js';
import { planImport, runImport } from './import.js';
import { isExpired } from './policy.js';
import { describeProfile, findProfile, isTrusted, mergeProfile, trustProfile } from './profile.js';
import { formatReport, installPreCommitHook, runScan } from './scan.js';
export async function cmdScan(store, args) {
    if (takeSwitch(args, '--install-hook')) {
        const hook = await installPreCommitHook(process.cwd(), takeSwitch(args, '--force'));
        return say(`✓ pre-commit hook installed: ${hook}`);
    }
    const staged = takeSwitch(args, '--staged');
    const transcripts = takeSwitch(args, '--transcripts');
    const localOnly = takeSwitch(args, '--local-only');
    const paths = args.length ? args : staged || transcripts ? [] : ['.'];
    const report = await runScan(store, { paths, staged, transcripts, localOnly });
    say(formatReport(report));
    if (report.findings.length)
        process.exit(1);
}
export async function cmdImport(store, args) {
    const prefix = takeFlag(args, '--prefix')[0];
    const only = takeList(args, '--only');
    const except = takeList(args, '--except');
    const all = takeSwitch(args, '--all');
    const overwrite = takeSwitch(args, '--overwrite');
    const remove = takeSwitch(args, '--remove');
    const yes = takeSwitch(args, '--yes');
    const dryRun = takeSwitch(args, '--dry-run');
    const file = args[0] ?? '.env';
    const opts = { prefix, only, except, all, overwrite };
    const plan = planImport(store, file, opts);
    if (plan.length === 0)
        return say(`(no entries in ${file})`);
    for (const p of plan) {
        const mark = !p.selected ? ' ' : p.skip ? '!' : '+';
        say(`${mark} ${p.key.padEnd(28)} → ${p.name.padEnd(28)} ${p.secretLike ? 'credential' : 'config'}${p.selected && p.skip ? `  (${p.skip})` : ''}`);
    }
    const todo = plan.filter(p => p.selected && !p.skip);
    if (todo.length === 0)
        return say('\nnothing to import (use --all or --only KEY,… to pick entries)');
    if (dryRun)
        return say(`\n${todo.length} entr${todo.length === 1 ? 'y' : 'ies'} would be imported`);
    if (!yes && !(await askYesNo(`\nImport ${todo.length} entr${todo.length === 1 ? 'y' : 'ies'}${remove ? ' and remove them from the file' : ''}?`))) {
        return say('aborted (non-interactive: add --yes)');
    }
    const result = await runImport(store, file, { ...opts, remove });
    for (const i of result.imported)
        say(`✓ ${i.key} → ${i.name}`);
    for (const s of result.skipped)
        say(`! ${s.key}: ${s.reason}`);
    if (result.profile) {
        trustProfile(result.profile); // the user just created it
        say(`✓ mapping written to ${result.profile.path} (safe to commit)`);
    }
    if (result.removedFromEnvFile.length)
        say(`✓ removed from ${file}: ${result.removedFromEnvFile.join(', ')}`);
    else if (result.imported.length)
        say(`  the values are still in ${file}; re-run with --remove or delete them by hand`);
    for (const w of result.warnings)
        say(`! ${w}`);
    if (result.imported.length)
        say('  start your app with: tresor run -- <command>');
}
export async function cmdProfile(args) {
    const sub = args.shift();
    if (sub === 'add' || sub === 'rm') {
        const dir = takeFlag(args, '--dir')[0] ?? process.cwd();
        if (args.length === 0)
            fail(`usage: tresor profile ${sub} ${sub === 'add' ? 'VAR=name …' : 'VAR …'}`);
        const mappings = sub === 'add' ? Object.fromEntries(args.map(m => {
            const eq = m.indexOf('=');
            if (eq <= 0)
                fail(`bad mapping "${m}", expected VAR=name`);
            return [m.slice(0, eq), m.slice(eq + 1)];
        })) : {};
        const profile = mergeProfile(dir, mappings, sub === 'rm' ? args : []);
        trustProfile(profile);
        say(`✓ ${profile.path}\n${describeProfile(profile) || '(empty)'}`);
        return;
    }
    const profile = findProfile();
    if (!profile)
        return say('(no .tresor.json in this directory or above)');
    if (sub === 'allow') {
        trustProfile(profile);
        return say(`✓ trusted ${profile.path}`);
    }
    say(`${profile.path}  ${isTrusted(profile) ? '(trusted)' : '(not trusted yet – tresor profile allow)'}\n${describeProfile(profile) || '(empty)'}`);
}
export function cmdInstall(args, uninstall) {
    const dryRun = takeSwitch(args, '--dry-run');
    const target = args[0] ?? fail(`usage: tresor ${uninstall ? 'uninstall' : 'install'} <${AGENTS.join('|')}|all> [--dry-run]`);
    if (target === 'claude') {
        return say('Claude Code: install the plugin instead – /plugin install tresor --marketplace Benewe1337/tresor');
    }
    const agents = target === 'all' ? detectAgents() : [target];
    if (target !== 'all' && !AGENTS.includes(target))
        fail(`unknown agent "${target}" (${AGENTS.join(', ')}, all)`);
    if (agents.length === 0)
        return say('no supported agent found (looked for Cursor, Codex, Gemini CLI, VS Code)');
    for (const agent of agents) {
        const r = (uninstall ? uninstallAgent : installAgent)(agent, { dryRun });
        say(`${uninstall ? '−' : '+'} ${agent}${dryRun ? ' (dry run)' : ''}`);
        for (const c of r.changes)
            if (c.action !== 'unchanged')
                say(`    ${c.action.padEnd(8)} ${c.file}`);
        for (const n of r.notes)
            say(`    → ${n}`);
    }
}
export function cmdLog(args) {
    const secret = takeFlag(args, '--secret')[0] ?? args[0];
    const limit = Number(takeFlag(args, '-n')[0] ?? 50);
    say(formatAudit(readAudit({ secret, limit })));
}
export function cmdPolicy(store, args) {
    const allow = takeList(args, '--allow-cmd');
    const clearAllow = takeSwitch(args, '--clear-allow-cmd');
    const confirm = takeFlag(args, '--confirm')[0];
    const expires = takeFlag(args, '--expires')[0];
    const hosts = takeList(args, '--host');
    const clearHosts = takeSwitch(args, '--clear-hosts');
    const name = args[0] ?? fail('usage: tresor policy <name> [--allow-cmd gh,git] [--confirm always|session|off] [--expires YYYY-MM-DD|off] [--host h] [--clear-hosts]');
    const changes = allow || clearAllow || confirm || expires || hosts || clearHosts;
    if (changes) {
        if (confirm && !['always', 'session', 'off'].includes(confirm))
            fail('--confirm must be always, session or off');
        if (expires && expires !== 'off' && Number.isNaN(Date.parse(expires)))
            fail('--expires must be a date like 2027-01-31 or "off"');
        const policy = {};
        if (allow || clearAllow)
            policy.allowCommands = clearAllow ? [] : allow.map(c => c.toLowerCase());
        if (confirm)
            policy.confirm = confirm === 'off' ? undefined : confirm;
        if (expires)
            policy.expiresAt = expires === 'off' ? undefined : new Date(expires).toISOString();
        store.updatePolicy(name, { hosts: clearHosts ? null : hosts, policy });
    }
    const meta = store.meta(name) ?? fail(`unknown secret "${name}"`);
    const p = meta.policy ?? {};
    say(`${name}
  hosts:         ${meta.hosts?.join(', ') ?? 'any'}
  allowed cmds:  ${p.allowCommands?.join(', ') ?? 'any'}
  confirm:       ${p.confirm ?? 'off'}
  expires:       ${p.expiresAt ? `${p.expiresAt.slice(0, 10)}${isExpired(p.expiresAt) ? '  ⚠ EXPIRED – rotate it' : ''}` : 'never'}`);
}
