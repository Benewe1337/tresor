import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { normalize, render } from '../src/agents/guard-formats.js';
import { detectAgents, guardCommand, installAgent, uninstallAgent, vscodeUserDir, type Runtime } from '../src/agents/install.js';
import { decideFor } from '../src/guard.js';

const rt: Runtime = {
  node: '/usr/local/bin/node',
  server: resolve('dist/server.js'),
  guard: resolve('dist/guard-bin.js'),
  skill: resolve('skills/tresor/SKILL.md'),
};
let home: string;
const now = new Date('2026-11-04T12:00:00Z');
const read = (...p: string[]) => JSON.parse(readFileSync(join(home, ...p), 'utf-8'));

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'tresor-agents-'));
  process.env.TRESOR_HOME = join(home, '.tresor-home');
});

describe('guard formats', () => {
  it('Cursor: shell/read events and explicit allow', () => {
    expect(decideFor('cursor', { hook_event_name: 'beforeShellExecution', command: 'op read op://a/b/c', cwd: '/' })).toMatch(/password-manager/);
    expect(decideFor('cursor', { hook_event_name: 'beforeShellExecution', command: 'ls', cwd: '/' })).toBeNull();
    expect(JSON.parse(render('cursor', null).stdout)).toEqual({ continue: true, permission: 'allow' });
    expect(JSON.parse(render('cursor', 'no').stdout)).toMatchObject({ permission: 'deny', agent_message: 'no' });
  });

  it('Gemini: tool names and tool_input', () => {
    expect(decideFor('gemini', { tool_name: 'run_shell_command', tool_input: { command: 'bw get password x' } })).toMatch(/password-manager/);
    expect(decideFor('gemini', { tool_name: 'write_file', tool_input: { file_path: join(process.env.TRESOR_HOME!, 'index.json') } })).toMatch(/managed by tresor/);
    expect(render('gemini', null).stdout).toBe('');
    expect(JSON.parse(render('gemini', 'r').stdout)).toEqual({ decision: 'deny', reason: 'r' });
  });

  it('Copilot: toolName with stringified toolArgs', () => {
    expect(decideFor('copilot', { toolName: 'bash', toolArgs: JSON.stringify({ command: 'tresor policy x --confirm off' }) })).toMatch(/humans/);
    expect(decideFor('copilot', { toolName: 'edit', toolArgs: { path: join(process.env.TRESOR_HOME!, 'trusted-profiles.json') } })).toMatch(/managed by tresor/);
    expect(JSON.parse(render('copilot', 'r').stdout)).toEqual({ permissionDecision: 'deny', permissionDecisionReason: 'r' });
  });

  it('Codex: shell tools and apply_patch paths', () => {
    expect(decideFor('claude', { tool_name: 'exec_command', tool_input: { command: ['bash', '-lc', 'gcloud auth print-access-token'] } })).toMatch(/password-manager/);
    const patch = `*** Begin Patch\n*** Update File: ${join(process.env.TRESOR_HOME!, 'index.json')}\n@@\n-a\n+b\n*** End Patch`;
    expect(decideFor('claude', { tool_name: 'apply_patch', tool_input: { command: patch } })).toMatch(/managed by tresor/);
    // A patch that merely *mentions* a blocked command in a README must not be refused.
    expect(normalize('claude', { tool_name: 'apply_patch', tool_input: { command: '*** Update File: README.md\n+run tresor rm x' } }))
      .toEqual([{ tool_name: 'Edit', tool_input: { file_path: 'README.md' }, cwd: undefined }]);
  });

  it('built guard honours --format and fails closed on garbage', () => {
    const bin = resolve('dist/guard-bin.js');
    const run = (fmt: string, input: string) => execFileSync(process.execPath, [bin, '--format', fmt], { input, env: { ...process.env } }).toString();
    expect(JSON.parse(run('cursor', JSON.stringify({ hook_event_name: 'beforeShellExecution', command: 'ls' }))).permission).toBe('allow');
    expect(JSON.parse(run('gemini', JSON.stringify({ tool_name: 'run_shell_command', tool_input: { command: 'vault kv get secret/x' } }))).decision).toBe('deny');
    expect(() => run('cursor', '{nope')).toThrow();
    expect(() => run('martian', '{}')).toThrow();
  });
});

describe('new guard rules', () => {
  const d = (command: string) => decideFor('claude', { tool_name: 'Bash', tool_input: { command } });
  it.each([
    'aws secretsmanager get-secret-value --secret-id x',
    'aws --profile dev configure export-credentials',
    'az keyvault secret show --vault-name v --name n',
    'az account get-access-token',
    'gcloud secrets versions access latest --secret s',
    'gcloud auth print-access-token',
    'doppler secrets get KEY --plain',
    'infisical sm secrets get KEY',
    'vault kv get secret/x',
    'bao read database/creds/app',
    'pass-cli item view pass://a/b/c',
    'dcli read dl://x/password',
    'keeper --batch-mode clipboard-copy --output stdout UID',
    'tresor dynamic x gcloud',
    'tresor install cursor',
  ])('denies: %s', cmd => expect(d(cmd)).not.toBeNull());

  it.each(['aws s3 ls', 'az account show', 'gcloud config list', 'doppler setup', 'vault status', 'tresor providers'])('allows: %s', cmd => expect(d(cmd)).toBeNull());
});

describe('tresor install', () => {
  it('Cursor: MCP + hooks + skill, merged into existing config and reversible', () => {
    mkdirSync(join(home, '.cursor'), { recursive: true });
    writeFileSync(join(home, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { other: { command: 'x' } } }));
    writeFileSync(join(home, '.cursor', 'hooks.json'), JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: 'mine.sh' }] } }));
    const r = installAgent('cursor', { home, runtime: rt, now });
    expect(read('.cursor', 'mcp.json').mcpServers).toEqual({ other: { command: 'x' }, tresor: { type: 'stdio', command: rt.node, args: [rt.server] } });
    const hooks = read('.cursor', 'hooks.json').hooks;
    expect(hooks.beforeShellExecution).toEqual([{ command: 'mine.sh' }, { command: guardCommand(rt, 'cursor'), failClosed: true, timeout: 15 }]);
    expect(hooks.preToolUse).toHaveLength(1);
    expect(readFileSync(join(home, '.agents', 'skills', 'tresor', 'SKILL.md'), 'utf-8')).toContain('name: tresor');
    expect(readdirSync(join(home, '.cursor')).some(f => f.startsWith('mcp.json.bak-tresor-'))).toBe(true);
    expect(r.notes.join()).toMatch(/Reload/);

    expect(installAgent('cursor', { home, runtime: rt, now }).changes.every(c => c.action === 'unchanged')).toBe(true);

    uninstallAgent('cursor', { home, now });
    expect(read('.cursor', 'mcp.json').mcpServers).toEqual({ other: { command: 'x' } });
    expect(read('.cursor', 'hooks.json').hooks).toEqual({ beforeShellExecution: [{ command: 'mine.sh' }] });
  });

  it('Codex: TOML table appended once and removed cleanly, hook group added', () => {
    mkdirSync(join(home, '.codex'), { recursive: true });
    const before = 'model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "x"\nargs = ["a"]\n';
    writeFileSync(join(home, '.codex', 'config.toml'), before);
    installAgent('codex', { home, runtime: rt, now });
    installAgent('codex', { home, runtime: rt, now });
    const toml = readFileSync(join(home, '.codex', 'config.toml'), 'utf-8');
    expect(toml.match(/\[mcp_servers\.tresor\]/g)).toHaveLength(1);
    expect(toml).toContain(`args = [${JSON.stringify(rt.server)}]`);
    expect(toml).toContain('[mcp_servers.other]');
    expect(read('.codex', 'hooks.json').hooks.PreToolUse[0].hooks[0].command).toBe(guardCommand(rt, 'claude'));
    uninstallAgent('codex', { home, now });
    expect(readFileSync(join(home, '.codex', 'config.toml'), 'utf-8').trim()).toBe(before.trim());
    expect(read('.codex', 'hooks.json').hooks).toEqual({});
  });

  it('Gemini: settings.json mcpServers + BeforeTool hook', () => {
    mkdirSync(join(home, '.gemini'), { recursive: true });
    writeFileSync(join(home, '.gemini', 'settings.json'), JSON.stringify({ theme: 'dark' }));
    installAgent('gemini', { home, runtime: rt, now });
    const s = read('.gemini', 'settings.json');
    expect(s.theme).toBe('dark');
    expect(s.mcpServers.tresor).toEqual({ command: rt.node, args: [rt.server] });
    expect(s.hooks.BeforeTool[0].matcher).toContain('run_shell_command');
    uninstallAgent('gemini', { home, now });
    expect(read('.gemini', 'settings.json')).toEqual({ theme: 'dark' });
  });

  it('VS Code: user mcp.json "servers" + Copilot hook file', () => {
    installAgent('vscode', { home, runtime: rt, now, platform: 'linux' });
    expect(read('.config', 'Code', 'User', 'mcp.json').servers.tresor.type).toBe('stdio');
    const hook = read('.copilot', 'hooks', 'tresor.json');
    expect(hook.hooks.preToolUse[0].bash).toBe(guardCommand(rt, 'copilot'));
    uninstallAgent('vscode', { home, now, platform: 'linux' });
    expect(existsSync(join(home, '.copilot', 'hooks', 'tresor.json'))).toBe(false);
    expect(read('.config', 'Code', 'User', 'mcp.json').servers).toEqual({});
  });

  it('refuses JSONC instead of destroying comments, and supports dry runs', () => {
    mkdirSync(join(home, '.cursor'), { recursive: true });
    writeFileSync(join(home, '.cursor', 'mcp.json'), '{ // comment\n "mcpServers": {} }');
    expect(() => installAgent('cursor', { home, runtime: rt, now })).toThrow(/not plain JSON/);
    const dry = installAgent('gemini', { home, runtime: rt, now, dryRun: true });
    expect(dry.changes.map(c => c.action)).toContain('created');
    expect(existsSync(join(home, '.gemini', 'settings.json'))).toBe(false);
  });

  it('detects installed agents by their config folders', () => {
    mkdirSync(join(home, '.codex'));
    mkdirSync(vscodeUserDir(home, 'darwin'), { recursive: true });
    expect(detectAgents(home, 'darwin')).toEqual(['codex', 'vscode']);
  });
});
