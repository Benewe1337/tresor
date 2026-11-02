/**
 * Native macOS input dialog (osascript, hidden answer). The value goes straight
 * from the dialog into this process and from here into the Keychain — the model
 * only ever learns whether the user saved or cancelled.
 */

import { execFile } from 'child_process';

const DIALOG_TIMEOUT_S = 300;

// argv is passed via `on run`, so the description can't inject AppleScript.
const SCRIPT = `
on run argv
  set promptText to item 1 of argv
  try
    set r to display dialog promptText default answer "" with hidden answer ¬
      with title "tresor" with icon caution ¬
      buttons {"Abbrechen", "Speichern"} default button "Speichern" cancel button "Abbrechen" ¬
      giving up after ${DIALOG_TIMEOUT_S}
  on error number -128
    return "CANCEL:"
  end try
  if gave up of r then return "TIMEOUT:"
  return "OK:" & (text returned of r)
end run`;

export type PromptResult = { status: 'ok'; value: string } | { status: 'cancelled' | 'timeout' };

export function promptSecret(name: string, description?: string): Promise<PromptResult> {
  if (process.platform !== 'darwin') {
    return Promise.reject(new Error(`No GUI prompt on ${process.platform}. Run in a terminal: tresor set ${name}`));
  }
  const text = `Wert für Secret „${name}" einfügen${description ? `\n\n${description}` : ''}\n\nWird im macOS-Schlüsselbund gespeichert. Claude sieht den Wert nicht.`;
  return new Promise((resolve, reject) => {
    execFile('osascript', ['-e', SCRIPT, text], { timeout: (DIALOG_TIMEOUT_S + 10) * 1000 }, (err, stdout) => {
      if (err) return reject(new Error(`Dialog failed: ${err.message.split('\n')[0]}`));
      const out = stdout.replace(/\n$/, '');
      if (out.startsWith('CANCEL:')) return resolve({ status: 'cancelled' });
      if (out.startsWith('TIMEOUT:')) return resolve({ status: 'timeout' });
      const value = out.slice('OK:'.length).trim();
      if (!value) return resolve({ status: 'cancelled' });
      resolve({ status: 'ok', value });
    });
  });
}
