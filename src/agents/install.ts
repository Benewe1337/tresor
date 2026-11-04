/**
 * `tresor install <agent>`: registers the MCP server, the guard hook and the skill
 * with other coding agents. Formats follow the vendors' docs as researched in
 * 2026-11; spots marked UNVERIFIED in the README could not be confirmed there.
 *
 * Every file is merged (never replaced), backed up before the first change, and
 * `tresor uninstall <agent>` removes exactly what was added.
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import type { GuardFormat } from './guard-formats.js';

export type AgentId = 'cursor' | 'codex' | 'gemini' | 'vscode';
export const AGENTS: readonly AgentId[] = ['cursor', 'codex', 'gemini', 'vscode'];

export interface Runtime {
  node: string;
  server: string;
  guard: string;
  skill: string;
}

export interface InstallOptions {
  home?: string;
  platform?: NodeJS.Platform;
  runtime?: Runtime;
  dryRun?: boolean;
  /** Fixed timestamp for backup names (tests). */
  now?: Date;
}

export interface FileChange { file: string; action: 'created' | 'updated' | 'unchanged' | 'removed' }
export interface InstallReport { agent: AgentId; changes: FileChange[]; notes: string[] }

const MARKER = 'tresor';

export function defaultRuntime(): Runtime {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  return {
    node: process.execPath,
    server: join(root, 'dist', 'server.js'),
    guard: join(root, 'dist', 'guard-bin.js'),
    skill: join(root, 'skills', 'tresor', 'SKILL.md'),
  };
}

const q = (s: string) => `"${s.replace(/"/g, '\\"')}"`;
export const guardCommand = (rt: Runtime, format: GuardFormat) => `${q(rt.node)} ${q(rt.guard)} --format ${format}`;
const isOurs = (cmd: unknown) => typeof cmd === 'string' && cmd.includes('guard-bin.js') && cmd.includes('--format');

class Ctx {
  readonly changes: FileChange[] = [];
  constructor(private readonly opts: Required<Pick<InstallOptions, 'dryRun'>> & { now: Date }) {}

  /** Writes `content` to `file` if it differs; backs up the previous version once per run. */
  write(file: string, content: string): void {
    const exists = existsSync(file);
    const prev = exists ? readFileSync(file, 'utf-8') : null;
    if (prev === content) { this.changes.push({ file, action: 'unchanged' }); return; }
    if (!this.opts.dryRun) {
      mkdirSync(dirname(file), { recursive: true });
      if (exists) copyFileSync(file, `${file}.bak-tresor-${this.opts.now.toISOString().replace(/[:.]/g, '-')}`);
      writeFileSync(file, content);
    }
    this.changes.push({ file, action: exists ? 'updated' : 'created' });
  }

  remove(file: string): void {
    if (!existsSync(file)) return;
    if (!this.opts.dryRun) rmSync(file, { force: true });
    this.changes.push({ file, action: 'removed' });
  }
}

/** Reads a JSON config; refuses JSONC (comments) instead of silently dropping them. */
function readJson(file: string): Record<string, unknown> {
  if (!existsSync(file)) return {};
  const raw = readFileSync(file, 'utf-8');
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw new Error(`${file} is not plain JSON (comments?). Add the tresor entries by hand – see README "Other agents".`);
  }
}

const json = (v: unknown) => JSON.stringify(v, null, 2) + '\n';
const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? { ...(v as Record<string, unknown>) } : {});

function mcpEntry(rt: Runtime, withType: boolean) {
  return withType ? { type: 'stdio', command: rt.node, args: [rt.server] } : { command: rt.node, args: [rt.server] };
}

function setMcp(ctx: Ctx, file: string, key: 'mcpServers' | 'servers', entry: unknown | null): void {
  const cfg = readJson(file);
  const servers = obj(cfg[key]);
  if (entry === null) {
    if (!(MARKER in servers)) return;
    delete servers[MARKER];
  } else {
    servers[MARKER] = entry;
  }
  ctx.write(file, json({ ...cfg, [key]: servers }));
}

function installSkill(ctx: Ctx, home: string, rt: Runtime): void {
  // ~/.agents/skills is read by Codex, Cursor, Gemini CLI and VS Code alike.
  ctx.write(join(home, '.agents', 'skills', 'tresor', 'SKILL.md'), readFileSync(rt.skill, 'utf-8'));
}

// ─── Cursor ──────────────────────────────────────────────────────────────────

const CURSOR_EVENTS = ['beforeShellExecution', 'beforeReadFile', 'preToolUse'] as const;

function cursor(ctx: Ctx, home: string, rt: Runtime | null): string[] {
  setMcp(ctx, join(home, '.cursor', 'mcp.json'), 'mcpServers', rt ? mcpEntry(rt, true) : null);
  const hooksFile = join(home, '.cursor', 'hooks.json');
  const cfg = readJson(hooksFile);
  const hooks = obj(cfg.hooks);
  for (const ev of CURSOR_EVENTS) {
    const list = (Array.isArray(hooks[ev]) ? hooks[ev] as Array<Record<string, unknown>> : []).filter(h => !isOurs(h.command));
    if (rt) list.push({ command: guardCommand(rt, 'cursor'), failClosed: true, timeout: 15 });
    if (list.length) hooks[ev] = list; else delete hooks[ev];
  }
  if (rt || existsSync(hooksFile)) ctx.write(hooksFile, json({ version: 1, ...cfg, hooks }));
  return rt ? ['Reload the Cursor window. Hooks fail closed: if tresor is removed, run `tresor uninstall cursor` first.'] : [];
}

// ─── OpenAI Codex ────────────────────────────────────────────────────────────

/** The [mcp_servers.tresor] table up to the next table header. */
const TOML_BLOCK_RE = /\n?\[mcp_servers\.tresor\][^\n]*\n(?:(?!\[)[^\n]*(?:\n|$))*/;

function codex(ctx: Ctx, home: string, rt: Runtime | null): string[] {
  const toml = join(home, '.codex', 'config.toml');
  const current = existsSync(toml) ? readFileSync(toml, 'utf-8') : '';
  const stripped = current.replace(TOML_BLOCK_RE, '\n').replace(/\n{3,}/g, '\n\n');
  const block = rt ? `\n[mcp_servers.tresor]\ncommand = ${JSON.stringify(rt.node)}\nargs = [${JSON.stringify(rt.server)}]\n` : '';
  if (rt || current !== stripped) ctx.write(toml, `${stripped.trimEnd()}${stripped.trim() ? '\n' : ''}${block}`.replace(/^\n+/, ''));

  const hooksFile = join(home, '.codex', 'hooks.json');
  const cfg = readJson(hooksFile);
  const hooks = obj(cfg.hooks);
  const groups = (Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse as Array<Record<string, unknown>> : [])
    .filter(g => !(Array.isArray(g.hooks) && (g.hooks as Array<Record<string, unknown>>).some(h => isOurs(h.command))));
  if (rt) groups.push({ matcher: '.*', hooks: [{ type: 'command', command: guardCommand(rt, 'claude'), timeout: 30 }] });
  if (groups.length) hooks.PreToolUse = groups; else delete hooks.PreToolUse;
  if (rt || existsSync(hooksFile)) ctx.write(hooksFile, json({ ...cfg, hooks }));
  return rt ? ['In Codex, run /hooks once and trust the tresor hook – Codex does not run untrusted hooks.'] : [];
}

// ─── Gemini CLI ──────────────────────────────────────────────────────────────

const GEMINI_MATCHER = 'run_shell_command|read_file|read_many_files|write_file|replace|grep_search|search_file_content|glob|list_directory';

function gemini(ctx: Ctx, home: string, rt: Runtime | null): string[] {
  const file = join(home, '.gemini', 'settings.json');
  const cfg = readJson(file);
  const servers = obj(cfg.mcpServers);
  if (rt) servers[MARKER] = mcpEntry(rt, false); else delete servers[MARKER];
  const hooks = obj(cfg.hooks);
  const groups = (Array.isArray(hooks.BeforeTool) ? hooks.BeforeTool as Array<Record<string, unknown>> : [])
    .filter(g => !(Array.isArray(g.hooks) && (g.hooks as Array<Record<string, unknown>>).some(h => isOurs(h.command))));
  if (rt) groups.push({ matcher: GEMINI_MATCHER, hooks: [{ name: 'tresor-guard', type: 'command', command: guardCommand(rt, 'gemini'), timeout: 15000 }] });
  if (groups.length) hooks.BeforeTool = groups; else delete hooks.BeforeTool;
  const next: Record<string, unknown> = { ...cfg, mcpServers: servers, hooks };
  if (!Object.keys(hooks).length) delete next.hooks;
  if (!Object.keys(servers).length) delete next.mcpServers;
  if (rt || existsSync(file)) ctx.write(file, json(next));
  return rt ? ['Restart Gemini CLI. (Google replaced Gemini CLI with Antigravity CLI for some account types; whether it reads the same settings is unverified.)'] : [];
}

// ─── VS Code / GitHub Copilot ────────────────────────────────────────────────

export function vscodeUserDir(home: string, platform: NodeJS.Platform): string {
  if (platform === 'darwin') return join(home, 'Library', 'Application Support', 'Code', 'User');
  if (platform === 'win32') return join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'Code', 'User');
  return join(home, '.config', 'Code', 'User');
}

function vscode(ctx: Ctx, home: string, rt: Runtime | null, platform: NodeJS.Platform): string[] {
  setMcp(ctx, join(vscodeUserDir(home, platform), 'mcp.json'), 'servers', rt ? mcpEntry(rt, true) : null);
  const hookFile = join(home, '.copilot', 'hooks', 'tresor.json');
  if (rt) {
    const cmd = guardCommand(rt, 'copilot');
    ctx.write(hookFile, json({ version: 1, hooks: { preToolUse: [{ type: 'command', bash: cmd, powershell: `& ${cmd}`, timeoutSec: 15 }] } }));
  } else {
    ctx.remove(hookFile);
  }
  return rt ? ['Reload VS Code. Hooks need "chat.useHooks" (default on); the hook file location for the local agent harness is unverified – check that a blocked command is reported.'] : [];
}

// ─── Entry points ────────────────────────────────────────────────────────────

function run(agent: AgentId, opts: InstallOptions, install: boolean): InstallReport {
  const home = opts.home ?? homedir();
  const rt = install ? (opts.runtime ?? defaultRuntime()) : null;
  if (rt) for (const f of [rt.server, rt.guard, rt.skill]) if (!existsSync(f)) throw new Error(`missing ${f} – run "npm run build" in the tresor folder`);
  const ctx = new Ctx({ dryRun: opts.dryRun ?? false, now: opts.now ?? new Date() });
  const notes = {
    cursor: () => cursor(ctx, home, rt),
    codex: () => codex(ctx, home, rt),
    gemini: () => gemini(ctx, home, rt),
    vscode: () => vscode(ctx, home, rt, opts.platform ?? process.platform),
  }[agent]();
  if (rt) installSkill(ctx, home, rt);
  return { agent, changes: ctx.changes, notes };
}

export const installAgent = (agent: AgentId, opts: InstallOptions = {}): InstallReport => run(agent, opts, true);
/** Removes tresor's entries; the shared skill in ~/.agents/skills stays (other agents may use it). */
export const uninstallAgent = (agent: AgentId, opts: InstallOptions = {}): InstallReport => run(agent, opts, false);

/** Agents whose config folder exists on this machine. */
export function detectAgents(home = homedir(), platform: NodeJS.Platform = process.platform): AgentId[] {
  const marks: Record<AgentId, string> = {
    cursor: join(home, '.cursor'),
    codex: join(home, '.codex'),
    gemini: join(home, '.gemini'),
    vscode: vscodeUserDir(home, platform),
  };
  return AGENTS.filter(a => existsSync(marks[a]));
}
