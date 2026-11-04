import { chompNewline, exec, onPath } from '../platform/exec.js';
import { ProviderError } from './types.js';
/** Run a provider CLI and return stdout without its trailing newline; throws with stderr on failure. */
export async function runCli(label, bin, args, opts = {}) {
    if (!onPath(bin, opts.env))
        throw new ProviderError(`${label}: "${bin}" is not installed or not on PATH.`);
    const r = await exec(bin, args, opts);
    if (r.timedOut)
        throw new ProviderError(`${label}: timed out (is the CLI waiting for input or an unlock?).`);
    if (r.code !== 0) {
        const msg = (r.stderr || r.stdout).trim().split('\n').slice(0, 3).join(' ');
        throw new ProviderError(`${label}: ${msg || `exit code ${r.code}`}`);
    }
    return chompNewline(r.stdout);
}
/** "path#field" → { path, field }. Splits on the LAST '#', so names may contain '#'. */
export function splitField(ref) {
    const i = ref.lastIndexOf('#');
    if (i <= 0 || i === ref.length - 1)
        return { path: ref };
    return { path: ref.slice(0, i), field: ref.slice(i + 1) };
}
export function notInstalled(bin) {
    return { installed: false, ready: false, detail: `${bin} not found` };
}
export function requireNonEmpty(label, ref, value) {
    if (!value)
        throw new ProviderError(`${label}: "${ref}" is empty.`);
    return value;
}
export function pickJson(json, path) {
    return path.split('.').reduce((cur, key) => (cur && typeof cur === 'object' ? cur[key] : undefined), json);
}
