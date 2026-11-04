import { exec, onPath } from '../platform/exec.js';
import { notInstalled, requireNonEmpty, runCli } from './common.js';
import { ProviderError, type Provider } from './types.js';

const OP_REF = /^op:\/\/[^/]+\/[^/]+\/.+/;

export const onePassword: Provider = {
  id: '1password',
  label: '1Password',
  refHelp: 'op://<Tresor>/<Eintrag>/<Feld>  (in 1Password: Feld → "Copy Secret Reference")',
  validateRef(ref) {
    if (!OP_REF.test(ref)) throw new ProviderError(`1Password-Referenz muss so aussehen: ${this.refHelp}`);
  },
  async resolve(ref, ctx) {
    this.validateRef(ref);
    return requireNonEmpty(this.label, ref, await runCli(this.label, 'op', ['read', '--no-newline', ref], { env: ctx.env }));
  },
  async status(ctx) {
    if (!onPath('op', ctx.env)) return notInstalled('op');
    if (ctx.env.OP_SERVICE_ACCOUNT_TOKEN) return { installed: true, ready: true, detail: 'Service-Account-Token gesetzt' };
    const r = await exec('op', ['whoami'], { env: ctx.env, timeoutMs: 15_000 });
    return r.code === 0
      ? { installed: true, ready: true, detail: 'angemeldet' }
      : { installed: true, ready: false, detail: 'nicht angemeldet – Desktop-App-Integration aktivieren oder `op signin`' };
  },
};
