/**
 * KeePassXC via `keepassxc-cli`. Database path (and optional key file) live in
 * providers.json; the database password is kept in the OS keychain
 * (`tresor setup keepassxc`) and piped to the CLI on stdin, never via argv.
 */

import { existsSync } from 'fs';
import { onPath } from '../platform/exec.js';
import { notInstalled, requireNonEmpty, runCli, splitField } from './common.js';
import { ProviderError, type Provider } from './types.js';

export const KEEPASS_PASSWORD_KEY = 'keepassxc.password';

export const keepassxc: Provider = {
  id: 'keepassxc',
  label: 'KeePassXC',
  refHelp: '<group/entry>[#attribute]  (default: Password; e.g. #UserName, #totp, custom attributes)',
  validateRef(ref) {
    if (!splitField(ref).path.trim()) throw new ProviderError(`KeePassXC reference: ${this.refHelp}`);
  },
  async resolve(ref, ctx) {
    this.validateRef(ref);
    const cfg = ctx.config.keepassxc;
    if (!cfg) throw new ProviderError('KeePassXC is not set up. In your terminal: tresor setup keepassxc --db <file.kdbx>');
    const { path, field = 'Password' } = splitField(ref);
    const password = cfg.noPassword ? null : ctx.internal.get(KEEPASS_PASSWORD_KEY);
    if (!cfg.noPassword && password === null) throw new ProviderError('KeePassXC password missing. In your terminal: tresor setup keepassxc --db <file.kdbx>');
    const args = [
      'show', '-q', '-s',
      ...(field.toLowerCase() === 'totp' ? ['--totp'] : ['-a', field]),
      ...(cfg.keyFile ? ['-k', cfg.keyFile] : []),
      ...(cfg.noPassword ? ['--no-password'] : []),
      cfg.database, path,
    ];
    const value = await runCli(this.label, 'keepassxc-cli', args, {
      env: ctx.env,
      input: password === null ? undefined : `${password}\n`,
    });
    return requireNonEmpty(this.label, ref, value);
  },
  async status(ctx) {
    if (!onPath('keepassxc-cli', ctx.env)) return notInstalled('keepassxc-cli');
    const cfg = ctx.config.keepassxc;
    if (!cfg) return { installed: true, ready: false, detail: 'not set up – run tresor setup keepassxc --db <file.kdbx>' };
    if (!existsSync(cfg.database)) return { installed: true, ready: false, detail: `database missing: ${cfg.database}` };
    const hasPw = cfg.noPassword || ctx.internal.get(KEEPASS_PASSWORD_KEY) !== null;
    return { installed: true, ready: hasPw, detail: hasPw ? cfg.database : 'password missing – run tresor setup keepassxc' };
  },
};
