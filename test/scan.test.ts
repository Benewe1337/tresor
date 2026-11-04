import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { beforeEach, describe, expect, it } from 'vitest';
import { formatReport, installPreCommitHook, runScan, Scanner, scanTranscripts } from '../src/scan.js';
import { MemoryBackend, SecretStore } from '../src/store.js';
import { Stubs } from './stubs.js';

const TOKEN = 'fake-scan-token-0123456789abc';
let dir: string;
let store: SecretStore;

beforeEach(() => {
  process.env.TRESOR_HOME = mkdtempSync(join(tmpdir(), 'tresor-scan-home-'));
  dir = mkdtempSync(join(tmpdir(), 'tresor-scan-'));
  store = new SecretStore(new MemoryBackend(), { providersConfig: {} });
  store.set('openai', TOKEN);
});

const git = (...args: string[]) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' }).toString();

describe('Scanner', () => {
  it('finds raw and encoded values with line numbers, never echoing the value', () => {
    const s = new Scanner({ openai: TOKEN });
    const b64 = Buffer.from(TOKEN).toString('base64');
    const findings = s.scanText(`a\nkey=${TOKEN}\nauth: ${b64}\n`, 'f');
    expect(findings).toEqual([
      { secret: 'openai', kind: 'base64', file: 'f', line: 3 },
      { secret: 'openai', kind: 'raw', file: 'f', line: 2 },
    ]);
    const text = formatReport({ findings, scannedFiles: 1, secretsChecked: ['openai'], warnings: [] });
    expect(text).not.toContain(TOKEN);
    expect(text).toMatch(/rotate/);
  });

  it('reports one finding per secret and line', () => {
    const s = new Scanner({ openai: TOKEN });
    expect(s.scanText(`${TOKEN} ${TOKEN}`, 'f')).toHaveLength(1);
  });
});

describe('runScan', () => {
  it('walks directories, skips node_modules and binaries', async () => {
    mkdirSync(join(dir, 'src'));
    mkdirSync(join(dir, 'node_modules'));
    writeFileSync(join(dir, 'src', 'config.ts'), `export const k = "${TOKEN}";\n`);
    writeFileSync(join(dir, 'node_modules', 'x.js'), TOKEN);
    writeFileSync(join(dir, 'img.bin'), Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(TOKEN)]));
    writeFileSync(join(dir, 'clean.md'), 'nothing here');
    const r = await runScan(store, { paths: [dir] });
    expect(r.findings.map(f => f.file)).toEqual([join(dir, 'src', 'config.ts')]);
    expect(r.secretsChecked).toEqual(['openai']);
  });

  it('warns about short values and unresolvable linked secrets instead of failing', async () => {
    store.set('pin', '1234');
    const stubs = new Stubs();
    const linked = new SecretStore(new MemoryBackend(), { providersConfig: {}, env: { PATH: stubs.dir } });
    linked.set('pin', '1234');
    linked.link('locked', 'bitwarden', 'X');
    const r = await runScan(linked, { paths: [dir] });
    expect(r.warnings.join('\n')).toMatch(/pin: shorter/);
    expect(r.warnings.join('\n')).toMatch(/locked: not checked/);
    const local = await runScan(linked, { paths: [dir], localOnly: true });
    expect(local.warnings.join('\n')).not.toMatch(/locked/);
  });

  it('checks the staged content, not the working tree', async () => {
    git('init', '-q');
    writeFileSync(join(dir, 'a.txt'), `token=${TOKEN}\n`);
    git('add', 'a.txt');
    writeFileSync(join(dir, 'a.txt'), 'cleaned in working tree only\n');
    const r = await runScan(store, { staged: true, cwd: dir });
    expect(r.findings).toEqual([{ secret: 'openai', kind: 'raw', file: 'a.txt', line: 1 }]);
  });

  it('scans Claude transcripts line by line (JSON-escaped values too)', async () => {
    const projects = join(dir, 'projects', 'p1');
    mkdirSync(projects, { recursive: true });
    const quoted = 'fake"quoted\\token-xyz-123';
    store.set('quoted', quoted);
    writeFileSync(join(projects, 's1.jsonl'), [
      JSON.stringify({ type: 'user', text: 'hello' }),
      JSON.stringify({ type: 'tool_result', text: `export K=${quoted}` }),
    ].join('\n') + '\n');
    const r = await scanTranscripts(new Scanner({ quoted }), join(dir, 'projects'));
    expect(r.findings).toEqual([{ secret: 'quoted', kind: 'json-escaped', file: join(projects, 's1.jsonl'), line: 2 }]);
  });
});

describe('pre-commit hook', () => {
  it('installs, is idempotent and refuses to overwrite foreign hooks', async () => {
    git('init', '-q');
    const hook = await installPreCommitHook(dir);
    expect(readFileSync(hook, 'utf-8')).toContain('tresor scan --staged');
    await installPreCommitHook(dir); // ours → fine to rewrite
    writeFileSync(hook, '#!/bin/sh\necho mine\n');
    await expect(installPreCommitHook(dir)).rejects.toThrow(/already exists/);
    await installPreCommitHook(dir, true);
    expect(readFileSync(hook, 'utf-8')).toContain('tresor:pre-commit');
  });

  it('fails outside a git repository', async () => {
    const outside = mkdtempSync(join(tmpdir(), 'tresor-nogit-'));
    expect(existsSync(join(outside, '.git'))).toBe(false);
    await expect(installPreCommitHook(outside)).rejects.toThrow(/Not inside a git repository/);
  });
});
