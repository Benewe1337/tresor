// Builds the Gemini CLI extension archive (build/tresor-gemini.tar.gz).
//
// Gemini always reads hooks/hooks.json in its own format, which collides with the
// Claude Code plugin's hooks/hooks.json at the repo root – so the extension ships
// as a release archive with its own manifest and hooks file at the archive root.
// Install: gemini extensions install https://github.com/Benewe1337/tresor
import { execFileSync } from 'child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';

const root = process.cwd();
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf-8'));
const out = join(root, 'build', 'gemini');
const json = (v) => JSON.stringify(v, null, 2) + '\n';

if (!existsSync(join(root, 'dist', 'server.js'))) throw new Error('run "npm run build" first');
rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, 'hooks'), { recursive: true });

for (const p of ['dist', 'plugin', 'skills', 'package.json', 'package-lock.json', 'LICENSE', 'README.md']) {
  cpSync(join(root, p), join(out, p), { recursive: true });
}

writeFileSync(join(out, 'gemini-extension.json'), json({
  name: 'tresor',
  version: pkg.version,
  description: 'Use API tokens without the agent ever seeing them: OS keychain, password managers, short-lived credentials, leak scanner.',
  mcpServers: {
    tresor: { command: 'node', args: ['${extensionPath}${/}plugin${/}launch.mjs', 'server'] },
  },
}));

writeFileSync(join(out, 'hooks', 'hooks.json'), json({
  hooks: {
    BeforeTool: [{
      matcher: 'run_shell_command|read_file|read_many_files|write_file|replace|grep_search|search_file_content|glob|list_directory',
      hooks: [{ name: 'tresor-guard', type: 'command', command: 'node "${extensionPath}/dist/guard-bin.js" --format gemini', timeout: 15000 }],
    }],
  },
}));

const archive = join(root, 'build', 'tresor-gemini.tar.gz');
execFileSync('tar', ['-czf', archive, '-C', out, '.']);
process.stdout.write(`${archive}\n`);
