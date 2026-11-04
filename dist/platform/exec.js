/**
 * Process helper shared by providers and platform code. Uses cross-spawn so
 * `.cmd` shims on Windows (bw, gopass via npm/scoop) work without a shell and
 * without hand-rolled argument escaping.
 */
import spawn from 'cross-spawn';
import { delimiter, join } from 'path';
import { existsSync } from 'fs';
export const DEFAULT_EXEC_TIMEOUT_MS = 60_000;
export function exec(cmd, args, opts = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, {
            env: opts.env ?? process.env,
            cwd: opts.cwd,
            stdio: [opts.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
            windowsHide: true,
        });
        const out = [];
        const err = [];
        child.stdout?.on('data', (d) => out.push(d));
        child.stderr?.on('data', (d) => err.push(d));
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; child.kill(); }, opts.timeoutMs ?? DEFAULT_EXEC_TIMEOUT_MS);
        child.on('error', e => { clearTimeout(timer); reject(e); });
        child.on('close', code => {
            clearTimeout(timer);
            resolve({ code, stdout: Buffer.concat(out).toString('utf-8'), stderr: Buffer.concat(err).toString('utf-8'), timedOut });
        });
        if (opts.input !== undefined && child.stdin) {
            child.stdin.on('error', () => { });
            child.stdin.end(opts.input);
        }
    });
}
/** True if `bin` is on PATH (honours PATHEXT on Windows). */
export function onPath(bin, env = process.env) {
    const exts = process.platform === 'win32' ? (env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';') : [''];
    const pathVar = env.PATH ?? env.Path ?? '';
    for (const dir of pathVar.split(delimiter)) {
        if (!dir)
            continue;
        for (const ext of exts) {
            if (existsSync(join(dir, bin + ext.toLowerCase())) || existsSync(join(dir, bin + ext)))
                return true;
        }
    }
    return false;
}
/** Strip exactly one trailing newline (CLIs add it; secrets may legitimately end in spaces). */
export function chompNewline(s) {
    return s.replace(/\r?\n$/, '');
}
