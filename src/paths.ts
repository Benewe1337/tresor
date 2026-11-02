import { homedir } from 'os';
import { join } from 'path';

/** Override with TRESOR_HOME (used by tests). Holds metadata only, never values. */
export function tresorHome(): string {
  return process.env.TRESOR_HOME ?? join(homedir(), '.config', 'tresor');
}

export const indexPath = (): string => join(tresorHome(), 'index.json');

/** Files tresor wrote secrets into; the guard hook blocks Claude from reading them. */
export const writtenFilesPath = (): string => join(tresorHome(), 'written-files.txt');
