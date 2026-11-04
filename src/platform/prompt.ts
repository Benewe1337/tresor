/**
 * Native dialogs for entering a secret or confirming an action. The value goes
 * from the dialog into this process only — the model learns ok/cancelled/timeout.
 *
 *   macOS   osascript (display dialog, hidden answer)
 *   Windows PowerShell + WinForms (password box / MessageBox)
 *   Linux   zenity or kdialog, else a one-shot form on 127.0.0.1 in the browser
 *
 * TRESOR_PROMPT=browser forces the browser form (e.g. WSL without dialogs).
 */

import { randomBytes } from 'crypto';
import { createServer } from 'http';
import { exec, onPath } from './exec.js';

export const DIALOG_TIMEOUT_S = 300;

export type PromptResult = { status: 'ok'; value: string } | { status: 'cancelled' | 'timeout' };
export type ConfirmResult = 'yes' | 'no' | 'timeout';
type Mode = 'secret' | 'confirm';

interface RawResult { status: 'ok' | 'cancelled' | 'timeout'; value: string }

const TIMEOUT_MS = (DIALOG_TIMEOUT_S + 15) * 1000;

function parseTagged(stdout: string): RawResult {
  const out = stdout.replace(/\r?\n$/, '');
  if (out.startsWith('OK:')) return { status: 'ok', value: out.slice(3) };
  if (out.startsWith('TIMEOUT:')) return { status: 'timeout', value: '' };
  return { status: 'cancelled', value: '' };
}

// ─── macOS ────────────────────────────────────────────────────────────────────

const OSA_SECRET = `
on run argv
  try
    set r to display dialog (item 1 of argv) default answer "" with hidden answer ¬
      with title "tresor" with icon caution buttons {"Cancel", "Save"} ¬
      default button "Save" cancel button "Cancel" giving up after ${DIALOG_TIMEOUT_S}
  on error number -128
    return "CANCEL:"
  end try
  if gave up of r then return "TIMEOUT:"
  return "OK:" & (text returned of r)
end run`;

const OSA_CONFIRM = `
on run argv
  try
    set r to display dialog (item 1 of argv) with title "tresor" with icon caution ¬
      buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" ¬
      giving up after ${DIALOG_TIMEOUT_S}
  on error number -128
    return "CANCEL:"
  end try
  if gave up of r then return "TIMEOUT:"
  return "OK:"
end run`;

async function macDialog(mode: Mode, text: string): Promise<RawResult> {
  const r = await exec('osascript', ['-e', mode === 'secret' ? OSA_SECRET : OSA_CONFIRM, text], { timeoutMs: TIMEOUT_MS });
  if (r.code !== 0) throw new Error(`Dialog failed: ${r.stderr.split('\n')[0]}`);
  return parseTagged(r.stdout);
}

// ─── Windows ──────────────────────────────────────────────────────────────────

// Text arrives via environment variable, so nothing in it is ever parsed as code.
const PS_SCRIPT = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$text = $env:TRESOR_PROMPT_TEXT
if ($env:TRESOR_PROMPT_MODE -eq 'confirm') {
  $r = [Windows.Forms.MessageBox]::Show($text, 'tresor', 'YesNo', 'Warning', 'Button2')
  if ($r -eq 'Yes') { 'OK:' } else { 'CANCEL:' }
  exit 0
}
$f = New-Object Windows.Forms.Form -Property @{ Text='tresor'; Width=470; Height=240; StartPosition='CenterScreen'; TopMost=$true; FormBorderStyle='FixedDialog'; MaximizeBox=$false; MinimizeBox=$false }
$l = New-Object Windows.Forms.Label -Property @{ Text=$text; Left=12; Top=12; Width=430; Height=96 }
$t = New-Object Windows.Forms.TextBox -Property @{ Left=12; Top=112; Width=430; UseSystemPasswordChar=$true }
$ok = New-Object Windows.Forms.Button -Property @{ Text='Save'; Left=272; Top=150; Width=80; DialogResult='OK' }
$c = New-Object Windows.Forms.Button -Property @{ Text='Cancel'; Left=362; Top=150; Width=80; DialogResult='Cancel' }
$f.Controls.AddRange(@($l, $t, $ok, $c)); $f.AcceptButton = $ok; $f.CancelButton = $c
$timer = New-Object Windows.Forms.Timer -Property @{ Interval = ${DIALOG_TIMEOUT_S * 1000} }
$timer.Add_Tick({ $f.Tag = 'timeout'; $f.Close() }); $timer.Start()
$f.Add_Shown({ $f.Activate(); $t.Focus() })
$r = $f.ShowDialog()
if ($f.Tag -eq 'timeout') { 'TIMEOUT:' } elseif ($r -eq 'OK') { 'OK:' + $t.Text } else { 'CANCEL:' }
`;

async function windowsDialog(mode: Mode, text: string): Promise<RawResult> {
  const encoded = Buffer.from(PS_SCRIPT, 'utf16le').toString('base64');
  const r = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
    env: { ...process.env, TRESOR_PROMPT_TEXT: text, TRESOR_PROMPT_MODE: mode },
    timeoutMs: TIMEOUT_MS,
  });
  if (r.code !== 0) throw new Error(`Dialog failed: ${r.stderr.split('\n')[0]}`);
  return parseTagged(r.stdout);
}

// ─── Linux ────────────────────────────────────────────────────────────────────

const pangoEscape = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

async function linuxDialog(mode: Mode, text: string): Promise<RawResult | null> {
  if (onPath('zenity')) {
    const args = mode === 'secret'
      ? ['--entry', '--hide-text', '--title=tresor', `--text=${pangoEscape(text)}`, `--timeout=${DIALOG_TIMEOUT_S}`]
      : ['--question', '--title=tresor', `--text=${pangoEscape(text)}`, '--ok-label=Allow', '--cancel-label=Deny', `--timeout=${DIALOG_TIMEOUT_S}`];
    const r = await exec('zenity', args, { timeoutMs: TIMEOUT_MS });
    if (r.code === 5) return { status: 'timeout', value: '' };
    return r.code === 0 ? { status: 'ok', value: r.stdout.replace(/\n$/, '') } : { status: 'cancelled', value: '' };
  }
  if (onPath('kdialog')) {
    const args = mode === 'secret' ? ['--title', 'tresor', '--password', text] : ['--title', 'tresor', '--warningyesno', text];
    const r = await exec('kdialog', args, { timeoutMs: TIMEOUT_MS });
    if (r.timedOut) return { status: 'timeout', value: '' };
    return r.code === 0 ? { status: 'ok', value: r.stdout.replace(/\n$/, '') } : { status: 'cancelled', value: '' };
  }
  return null;
}

// ─── Browser fallback ─────────────────────────────────────────────────────────

const htmlEscape = (s: string) => s.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);

function formHtml(mode: Mode, text: string, token: string): string {
  const field = mode === 'secret'
    ? '<input type="password" name="value" autofocus autocomplete="off" required><button name="action" value="ok">Save</button>'
    : '<button name="action" value="ok">Allow</button>';
  return `<!doctype html><meta charset="utf-8"><title>tresor</title>
<style>body{font:15px system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}p{white-space:pre-wrap}
input{width:100%;padding:.5rem;margin:.5rem 0;box-sizing:border-box}button{padding:.5rem 1rem;margin-right:.5rem}</style>
<h1>tresor</h1><p>${htmlEscape(text)}</p>
<form method="post" action="/${token}">${field}<button name="action" value="cancel" formnovalidate>${mode === 'secret' ? 'Cancel' : 'Deny'}</button></form>`;
}

function openUrl(url: string): void {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [url]]
    : process.platform === 'win32' ? ['rundll32', ['url.dll,FileProtocolHandler', url]]
    : ['xdg-open', [url]];
  exec(cmd, args as string[], { timeoutMs: 10_000 }).catch(() => { /* URL is also printed to stderr */ });
}

export function browserDialog(mode: Mode, text: string, open: (url: string) => void = openUrl): Promise<RawResult> {
  const token = randomBytes(24).toString('hex');
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (r: RawResult) => { if (!settled) { settled = true; clearTimeout(timer); server.close(); resolve(r); } };
    const server = createServer((req, res) => {
      if (req.url !== `/${token}`) { res.writeHead(404).end(); return; }
      if (req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(formHtml(mode, text, token));
        return;
      }
      if (req.method !== 'POST') { res.writeHead(405).end(); return; }
      let body = '';
      req.on('data', (d: Buffer) => { body += d.toString('utf-8'); if (body.length > 64 * 1024) req.destroy(); });
      req.on('end', () => {
        const form = new URLSearchParams(body);
        const ok = form.get('action') === 'ok';
        const value = (form.get('value') ?? '').trim();
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<meta charset="utf-8">Done – you can close this tab.');
        finish(ok && (mode === 'confirm' || value) ? { status: 'ok', value } : { status: 'cancelled', value: '' });
      });
    });
    const timer = setTimeout(() => finish({ status: 'timeout', value: '' }), DIALOG_TIMEOUT_S * 1000);
    server.on('error', e => { if (!settled) { settled = true; clearTimeout(timer); reject(e); } });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      const url = `http://127.0.0.1:${port}/${token}`;
      process.stderr.write(`[tresor] enter the value in your browser: ${url}\n`);
      open(url);
    });
  });
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

const hasLinuxDesktop = () => Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);

async function dialog(mode: Mode, text: string): Promise<RawResult> {
  if (process.env.TRESOR_PROMPT === 'browser') return browserDialog(mode, text);
  if (process.platform === 'darwin') return macDialog(mode, text);
  if (process.platform === 'win32') return windowsDialog(mode, text);
  if (!hasLinuxDesktop()) {
    throw new Error('No desktop (DISPLAY/WAYLAND_DISPLAY) for a dialog. In your terminal: tresor set <name>, or set TRESOR_PROMPT=browser.');
  }
  return (await linuxDialog(mode, text)) ?? browserDialog(mode, text);
}

export async function promptSecret(name: string, description?: string): Promise<PromptResult> {
  const text = `Paste the value for secret "${name}"${description ? `\n\n${description}` : ''}\n\nIt is stored in your system keychain. Claude never sees the value.`;
  const r = await dialog('secret', text);
  if (r.status !== 'ok') return { status: r.status };
  const value = r.value.trim();
  return value ? { status: 'ok', value } : { status: 'cancelled' };
}

export async function confirm(text: string): Promise<ConfirmResult> {
  const r = await dialog('confirm', text);
  return r.status === 'ok' ? 'yes' : r.status === 'timeout' ? 'timeout' : 'no';
}
