import { chompNewline, exec, onPath, type ExecOptions } from '../platform/exec.js';
import { ProviderError, type ProviderStatus } from './types.js';

/** Run a provider CLI and return stdout without its trailing newline; throws with stderr on failure. */
export async function runCli(label: string, bin: string, args: string[], opts: ExecOptions = {}): Promise<string> {
  if (!onPath(bin, opts.env)) throw new ProviderError(`${label}: "${bin}" ist nicht installiert bzw. nicht im PATH.`);
  const r = await exec(bin, args, opts);
  if (r.timedOut) throw new ProviderError(`${label}: Zeitüberschreitung (wartet die CLI auf eine Eingabe/Entsperrung?).`);
  if (r.code !== 0) {
    const msg = (r.stderr || r.stdout).trim().split('\n').slice(0, 3).join(' ');
    throw new ProviderError(`${label}: ${msg || `Exit-Code ${r.code}`}`);
  }
  return chompNewline(r.stdout);
}

/** "path#field" → { path, field }. Splits on the LAST '#', so names may contain '#'. */
export function splitField(ref: string): { path: string; field?: string } {
  const i = ref.lastIndexOf('#');
  if (i <= 0 || i === ref.length - 1) return { path: ref };
  return { path: ref.slice(0, i), field: ref.slice(i + 1) };
}

export function notInstalled(bin: string): ProviderStatus {
  return { installed: false, ready: false, detail: `${bin} nicht gefunden` };
}

export function requireNonEmpty(label: string, ref: string, value: string): string {
  if (!value) throw new ProviderError(`${label}: "${ref}" ist leer.`);
  return value;
}

export function pickJson(json: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((cur, key) => (cur && typeof cur === 'object' ? (cur as Record<string, unknown>)[key] : undefined), json);
}
