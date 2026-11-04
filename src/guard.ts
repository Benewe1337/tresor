/**
 * Claude Code PreToolUse hook (`tresor-guard`): keeps the model from reading secret
 * values *around* the MCP server — straight from the OS credential store, from a
 * password-manager CLI, or from files tresor_write_file filled in.
 *
 * Works on macOS, Linux and Windows (Bash and PowerShell tools). Defense in depth
 * against accidents, not a sandbox — see README "Bedrohungsmodell".
 */

import { existsSync, readFileSync } from 'fs';
import { homedir } from 'os';
import { isAbsolute, join, relative } from 'path';
import { tresorHome, writtenFilesPath } from './paths.js';

export interface HookInput {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  cwd?: string;
}

/** Matches `bin sub…` in command position (start, after ; & | ( or $( ), with optional path, sudo/env, .exe/.cmd. */
function cmd(bin: string, sub: string): RegExp {
  const pre = String.raw`(?:^|[;&|({\`\n]|\$\()\s*(?:(?:sudo|exec|command|nohup|time)\s+|env\s+(?:\S+=\S*\s+)*)*(?:[^\s;&|()]*[\\/])?`;
  return new RegExp(`${pre}${bin}(?:\\.exe|\\.cmd)?\\s+${sub}`, 'i');
}

const LIST_ONLY = String.raw`(?!(?:ls|list|find|search|help|version|init|setup|--help|-h)\b)\S`;

interface Rule { re: RegExp; reason: string }

const KEYSTORE = 'No direct keychain access. Use the tresor_* MCP tools (tresor_run, tresor_http).';
const MANAGER = 'Do not read password-manager values directly. Link them with tresor_link, use them via tresor_run/tresor_http.';

export const RULES: readonly Rule[] = [
  // OS credential stores
  { re: /(find|dump)-(generic|internet)-password|dump-keychain|export-keychain|\bsecurity\s+-i\b/i, reason: KEYSTORE },
  { re: cmd('secret-tool', '(lookup|search)'), reason: KEYSTORE },
  { re: cmd('keyctl', '(print|pipe|read)'), reason: KEYSTORE },
  { re: /Get-StoredCredential|CredRead|PasswordVault|Windows\.Security\.Credentials|CredentialManager/i, reason: KEYSTORE },
  { re: /@napi-rs\/keyring|\bkeytar\b|\bimport\s+keyring\b|\bfrom\s+keyring\b|\bkeyring\s+get\b/i, reason: KEYSTORE },
  // Password-manager CLIs
  { re: cmd('op', '(read|inject|run|signin|item\\s+get|document\\s+get)'), reason: MANAGER },
  { re: cmd('bw', '(get|unlock|login|export|list|serve|send)'), reason: MANAGER },
  { re: cmd('bws', '(secret|run)'), reason: MANAGER },
  { re: cmd('keepassxc-cli', '(show|export|clip|attachment-export|totp)'), reason: MANAGER },
  { re: cmd('pass', LIST_ONLY), reason: MANAGER },
  { re: cmd('gopass', LIST_ONLY), reason: MANAGER },
  { re: cmd('lpass', '(show|export)'), reason: MANAGER },
  // tresor's own human-only commands
  { re: cmd('tresor', '(set|rm|delete|run|unlock|lock|setup|link|policy)\\b'), reason: 'tresor set/rm/run/link/unlock/setup/policy are for humans in their own terminal. Claude uses tresor_request, tresor_link, tresor_run.' },
  { re: cmd('tresor', 'profile\\s+(allow|add|rm)\\b'), reason: 'Trusting or changing a tresor project profile is up to the user (tresor profile allow/add in their own terminal).' },
];

const HOME_REASON = 'The tresor folder (index, policies, trusted profiles, log) is managed by tresor only. Use tresor_list / tresor_log to read it.';
const EDIT_TOOLS = new Set(['Edit', 'Write', 'NotebookEdit', 'MultiEdit']);

/** Text forms of the tresor folder a command might use. */
function homeNeedles(home: string): string[] {
  const n = norm(home);
  return [n, n.replace(homedir().replace(/\\/g, '/').toLowerCase(), '~'), n.replace(norm(homedir()), '~'), '$TRESOR_HOME', '%APPDATA%\\tresor', 'appdata/roaming/tresor', '.config/tresor']
    .map(s => s.toLowerCase())
    .filter((s, i, all) => s.length > 1 && all.indexOf(s) === i);
}

function touchesHome(text: string, home: string): boolean {
  const t = norm(text).toLowerCase().replace(/\\/g, '/');
  return homeNeedles(home).some(n => t.includes(n.replace(/\\/g, '/')));
}

const COMMAND_TOOLS = new Set(['Bash', 'PowerShell']);
const norm = (p: string) => (process.platform === 'win32' ? p.replace(/\\/g, '/').toLowerCase() : p);

function writtenFiles(registry: string): string[] {
  if (!existsSync(registry)) return [];
  return readFileSync(registry, 'utf-8').split(/\r?\n/).filter(Boolean);
}

/** Returns a deny reason, or null to let the tool call through. */
export function decide(input: HookInput, registry = writtenFilesPath(), home = tresorHome()): string | null {
  const tool = input.tool_name ?? '';
  const ti = input.tool_input ?? {};
  const command = typeof ti.command === 'string' ? ti.command : '';
  const pathArg = [ti.file_path, ti.path, ti.notebook_path].find((v): v is string => typeof v === 'string');
  const cwd = input.cwd ?? '';

  if (COMMAND_TOOLS.has(tool) && command) {
    const hit = RULES.find(r => r.re.test(command));
    if (hit) return `tresor-guard: ${hit.reason}`;
    if (touchesHome(command, home)) return `tresor-guard: ${HOME_REASON}`;
  }
  if (EDIT_TOOLS.has(tool) && pathArg) {
    const abs = cwd && !isAbsolute(pathArg) ? join(cwd, pathArg) : pathArg;
    if (touchesHome(abs, home)) return `tresor-guard: ${HOME_REASON}`;
  }

  const files = writtenFiles(registry);
  if (files.length === 0) return null;
  const target = norm(COMMAND_TOOLS.has(tool) ? command : pathArg && cwd && !isAbsolute(pathArg) ? join(cwd, pathArg) : pathArg ?? '');
  if (!target) return null;
  for (const f of files) {
    const rel = cwd ? relative(cwd, f) : '';
    const candidates = [norm(f), ...(rel && !rel.startsWith('..') ? [norm(rel)] : [])];
    if (candidates.some(c => target.includes(c))) return `tresor-guard: ${f} contains injected secrets and is off-limits to Claude.`;
  }
  return null;
}

export async function main(): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  let input: HookInput;
  try {
    input = JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}') as HookInput;
  } catch {
    process.stderr.write('tresor-guard: invalid hook input\n');
    process.exit(2); // blocking error: fail closed
  }
  const reason = decide(input);
  if (reason) {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }));
  }
}
