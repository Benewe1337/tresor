import { execFileSync } from 'child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { beforeAll, describe, expect, it } from 'vitest';
import { decide } from '../src/guard.js';

let registry: string;
const FILE = process.platform === 'win32' ? 'C:\\Users\\x\\proj\\.env' : '/Users/x/proj/.env';
const DIR = process.platform === 'win32' ? 'C:\\Users\\x\\proj' : '/Users/x/proj';

const bash = (command: string, cwd = '/tmp') => decide({ tool_name: 'Bash', tool_input: { command }, cwd }, registry) ? 'deny' : 'allow';

beforeAll(() => {
  registry = join(mkdtempSync(join(tmpdir(), 'tresor-guard-')), 'written-files.txt');
  writeFileSync(registry, `${FILE}\n`);
});

describe('tresor-guard', () => {
  it.each([
    'security find-generic-password -s tresor -a openai -w',
    'security dump-keychain -d',
    'secret-tool lookup service tresor',
    'keyctl print 1234',
    'node -e "require(\'@napi-rs/keyring\')"',
    'python -c "import keyring; print(keyring.get_password(\'tresor\',\'x\'))"',
    'op read op://Private/OpenAI/credential',
    'op item get OpenAI --fields credential',
    'cd x && bw get password github',
    'bw list items --search git',
    'bw unlock --raw',
    '/opt/homebrew/bin/bw get item x',
    'bws secret get 0f8f',
    'keepassxc-cli show -s db.kdbx Web/GitHub',
    'pass show api/openai',
    'pass api/openai',
    'gopass show -o api/openai',
    'lpass show --password Work/API',
    'echo $(op read op://a/b/c)',
    'sudo bw get password x',
    'tresor run -e K=openai -- env',
    'tresor link x pass a/b',
    'tresor setup keepassxc --db x',
    '~/bin/tresor rm openai',
  ])('denies: %s', cmd => expect(bash(cmd)).toBe('deny'));

  it.each([
    'tresor list', 'tresor providers', 'tresor --help', 'git status', 'npm run build',
    'security list-keychains', 'bw status', 'bw --version', 'op --version', 'op whoami',
    'pass ls', 'pass', 'gopass ls', 'echo "you shall pass the test"', 'grep -r password src/', 'npm i passport',
  ])('allows: %s', cmd => expect(bash(cmd)).toBe('allow'));

  it('also covers the PowerShell tool and Windows credential APIs', () => {
    const ps = (command: string) => decide({ tool_name: 'PowerShell', tool_input: { command } }, registry);
    expect(ps('Get-StoredCredential -Target tresor')).not.toBeNull();
    expect(ps('[Windows.Security.Credentials.PasswordVault]::new()')).not.toBeNull();
    expect(ps('& bw.exe get password x')).not.toBeNull();
    expect(ps('Get-ChildItem')).toBeNull();
  });

  it('blocks reading written files by absolute and relative path', () => {
    expect(decide({ tool_name: 'Read', tool_input: { file_path: FILE } }, registry)).toMatch(/gesperrt/);
    expect(decide({ tool_name: 'Grep', tool_input: { pattern: 'KEY', path: '.env' }, cwd: DIR }, registry)).toMatch(/gesperrt/);
    expect(bash('cat .env', DIR)).toBe('deny');
    expect(decide({ tool_name: 'Read', tool_input: { file_path: join(DIR, 'README.md') } }, registry)).toBeNull();
  });

  it('built hook speaks the Claude Code hook protocol', () => {
    const bin = resolve('dist/guard-bin.js');
    expect(existsSync(bin), 'run npm run build first').toBe(true);
    const run = (input: string) => execFileSync(process.execPath, [bin], { input, env: { ...process.env, TRESOR_HOME: join(registry, '..') } }).toString();
    const out = JSON.parse(run(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'op read op://a/b/c' } })));
    expect(out.hookSpecificOutput).toMatchObject({ hookEventName: 'PreToolUse', permissionDecision: 'deny' });
    expect(run(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } }))).toBe('');
    expect(() => run('not json')).toThrow(); // exit 2 = fail closed
  });
});
