import { homedir } from 'os';
import { join } from 'path';
/**
 * Override with TRESOR_HOME (used by tests). Holds metadata only, never values.
 * Default: ~/.config/tresor on macOS/Linux (XDG_CONFIG_HOME honoured), %APPDATA%\tresor on Windows.
 */
export function tresorHome() {
    if (process.env.TRESOR_HOME)
        return process.env.TRESOR_HOME;
    if (process.platform === 'win32')
        return join(process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), 'tresor');
    return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'tresor');
}
export const indexPath = () => join(tresorHome(), 'index.json');
/** Non-secret provider settings (KeePassXC database path, custom providers). */
export const providersConfigPath = () => join(tresorHome(), 'providers.json');
/** Files tresor wrote secrets into; the guard hook blocks Claude from reading them. */
export const writtenFilesPath = () => join(tresorHome(), 'written-files.txt');
