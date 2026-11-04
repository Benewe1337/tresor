/**
 * Append-only usage log (JSON lines) in the tresor folder: which secret was used,
 * when, by whom (mcp/cli) and for what (command, host, file). Never values.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from 'fs';
import { dirname } from 'path';
import { auditLogPath } from './paths.js';

export type AuditAction = 'run' | 'http' | 'write_file' | 'scan' | 'import' | 'link' | 'request';

export interface AuditEntry {
  ts: string;
  via: 'mcp' | 'cli';
  action: AuditAction;
  secrets: string[];
  /** Human-readable target: command name, METHOD host, file path … */
  detail: string;
  ok: boolean;
  error?: string;
}

const ROTATE_BYTES = 5 * 1024 * 1024;

export function appendAudit(entry: Omit<AuditEntry, 'ts'>, path = auditLogPath()): void {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    if (existsSync(path) && statSync(path).size > ROTATE_BYTES) renameSync(path, `${path}.1`);
    appendFileSync(path, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
  } catch (e) {
    // Logging must never break a tool call; surface it on stderr instead.
    process.stderr.write(`[tresor] audit log write failed: ${e instanceof Error ? e.message : String(e)}\n`);
  }
}

export function readAudit(opts: { secret?: string; limit?: number } = {}, path = auditLogPath()): AuditEntry[] {
  if (!existsSync(path)) return [];
  const entries = readFileSync(path, 'utf-8').split('\n').filter(Boolean).flatMap(line => {
    try { return [JSON.parse(line) as AuditEntry]; } catch { return []; }
  });
  const filtered = opts.secret ? entries.filter(e => e.secrets.includes(opts.secret!)) : entries;
  return filtered.slice(-(opts.limit ?? 50));
}

export function formatAudit(entries: AuditEntry[]): string {
  if (entries.length === 0) return '(no entries)';
  return entries.map(e => {
    const status = e.ok ? ' ' : '✗';
    return `${status} ${e.ts.replace('T', ' ').slice(0, 19)}  ${e.via.padEnd(3)}  ${e.action.padEnd(10)} ${e.secrets.join(',').padEnd(24)} ${e.detail}${e.error ? `  (${e.error})` : ''}`;
  }).join('\n');
}
