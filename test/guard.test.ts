import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { beforeAll, describe, expect, it } from 'vitest';

const HOOK = resolve('hooks/tresor-guard.sh');
let home: string;

function decide(input: Record<string, unknown>): string {
  const out = execFileSync('bash', [HOOK], { input: JSON.stringify(input), env: { ...process.env, TRESOR_HOME: home } }).toString();
  return out ? JSON.parse(out).hookSpecificOutput.permissionDecision : 'allow';
}
const bash = (command: string, cwd = '/tmp') => decide({ tool_name: 'Bash', tool_input: { command }, cwd });

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'tresor-guard-'));
  writeFileSync(join(home, 'written-files.txt'), '/Users/x/proj/.env\n');
});

describe('tresor-guard hook', () => {
  it.each([
    'security find-generic-password -s tresor -a openai -w',
    'security dump-keychain -d',
    'node -e "require(\'@napi-rs/keyring\')"',
    'tresor run -e K=openai -- env',
    'cd x && tresor set foo',
    '~/bin/tresor rm openai',
    'cat /Users/x/proj/.env',
  ])('denies: %s', cmd => expect(bash(cmd)).toBe('deny'));

  it('denies relative access to a written file', () => {
    expect(bash('grep KEY .env', '/Users/x/proj')).toBe('deny');
  });

  it.each(['tresor list', 'tresor --help', 'git status', 'security list-keychains', 'npm run build'])(
    'allows: %s', cmd => expect(bash(cmd)).toBe('allow'),
  );

  it('blocks Read on written files only', () => {
    expect(decide({ tool_name: 'Read', tool_input: { file_path: '/Users/x/proj/.env' }, cwd: '/' })).toBe('deny');
    expect(decide({ tool_name: 'Read', tool_input: { file_path: '/Users/x/proj/README.md' }, cwd: '/' })).toBe('allow');
  });
});
