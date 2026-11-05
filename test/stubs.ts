/**
 * Fake password-manager CLIs for tests. Each stub logs its argv, selected env and
 * stdin to calls.jsonl and answers from a response table — cross-platform
 * (shebang script on POSIX, .cmd shim on Windows).
 */

import { chmodSync, mkdtempSync, readFileSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { delimiter, dirname, join } from 'path';

export interface StubResponse { match: string[]; stdout?: string; stderr?: string; code?: number }
export interface StubCall { bin: string; argv: string[]; env: Record<string, string | undefined>; stdin: string }

const STUB_SOURCE = (bin: string, dir: string) => `
const fs = require('fs');
const path = require('path');
const dir = ${JSON.stringify(dir)};
const argv = process.argv.slice(2);
let stdin = '';
try { stdin = fs.readFileSync(0, 'utf8'); } catch {}
const env = {};
for (const k of ['BW_SESSION', 'BWS_ACCESS_TOKEN', 'OP_SERVICE_ACCOUNT_TOKEN']) env[k] = process.env[k];
fs.appendFileSync(path.join(dir, 'calls.jsonl'), JSON.stringify({ bin: ${JSON.stringify(bin)}, argv, env, stdin }) + '\\n');
const table = JSON.parse(fs.readFileSync(path.join(dir, ${JSON.stringify(bin)} + '.json'), 'utf8'));
const hit = table.find(r => r.match.every((m, i) => argv[i] === m));
if (!hit) { process.stderr.write('stub: no response for ' + argv.join(' ')); process.exit(97); }
if (hit.stdout) process.stdout.write(hit.stdout);
if (hit.stderr) process.stderr.write(hit.stderr);
process.exit(hit.code ?? 0);
`;

export class Stubs {
  readonly dir = mkdtempSync(join(tmpdir(), 'tresor-stubs-'));

  /**
   * Env whose PATH holds only the stubs and node. Real CLIs on the machine (CI
   * runners ship aws, az, gcloud …) must never be reached by provider tests.
   */
  env(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
    const { Path: _winPath, ...rest } = process.env;
    return { ...rest, PATH: `${this.dir}${delimiter}${dirname(process.execPath)}`, ...extra };
  }

  add(bin: string, responses: StubResponse[]): this {
    writeFileSync(join(this.dir, `${bin}.json`), JSON.stringify(responses));
    const script = join(this.dir, `${bin}.cjs`);
    writeFileSync(script, STUB_SOURCE(bin, this.dir));
    if (process.platform === 'win32') {
      writeFileSync(join(this.dir, `${bin}.cmd`), `@"${process.execPath}" "%~dp0${bin}.cjs" %*\r\n`);
    } else {
      const exe = join(this.dir, bin);
      writeFileSync(exe, `#!${process.execPath}\nrequire(${JSON.stringify(script)});\n`);
      chmodSync(exe, 0o755);
    }
    return this;
  }

  calls(bin?: string): StubCall[] {
    const log = join(this.dir, 'calls.jsonl');
    if (!existsSync(log)) return [];
    return readFileSync(log, 'utf-8').split('\n').filter(Boolean).map(l => JSON.parse(l) as StubCall)
      .filter(c => !bin || c.bin === bin);
  }
}
