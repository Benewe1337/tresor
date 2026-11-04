/** Read the clipboard once and clear it afterwards (for `tresor set --clip`). */
import { exec, onPath } from './exec.js';
const PS = ['-NoProfile', '-NonInteractive', '-STA', '-Command'];
function tool() {
    if (process.platform === 'darwin')
        return { read: ['pbpaste', []], clear: ['pbcopy', []] };
    if (process.platform === 'win32') {
        return {
            read: ['powershell.exe', [...PS, '[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw']],
            clear: ['powershell.exe', [...PS, 'Add-Type -AssemblyName System.Windows.Forms; [Windows.Forms.Clipboard]::Clear()']],
        };
    }
    if (process.env.WAYLAND_DISPLAY && onPath('wl-paste'))
        return { read: ['wl-paste', ['--no-newline']], clear: ['wl-copy', ['--clear']] };
    if (onPath('xclip'))
        return { read: ['xclip', ['-o', '-selection', 'clipboard']], clear: ['xclip', ['-i', '-selection', 'clipboard']] };
    if (onPath('xsel'))
        return { read: ['xsel', ['--clipboard', '--output']], clear: ['xsel', ['--clipboard', '--clear']] };
    throw new Error('No clipboard tool found (install wl-clipboard, xclip or xsel).');
}
export async function takeClipboard() {
    const t = tool();
    const r = await exec(...t.read, { timeoutMs: 10_000 });
    if (r.code !== 0)
        throw new Error(`Reading the clipboard failed: ${r.stderr.trim()}`);
    // pbcopy/xclip -i clear by reading an empty stdin.
    await exec(...t.clear, { input: '', timeoutMs: 10_000 });
    return r.stdout.trim();
}
