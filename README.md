# tresor

**Let Claude Code use your API tokens without ever seeing them.**

Tokens live in your operating system's keychain or stay in your password manager. Claude works with names (`openai`, `github`); tresor injects the real value into the command, HTTP request or `.env` file and redacts it from everything Claude gets back.

- Works on **macOS, Windows and Linux**
- Reads from **1Password, Bitwarden / Vaultwarden, Bitwarden Secrets Manager, KeePassXC, pass, gopass, LastPass** or any CLI you configure
- No server, no extra master password, nothing leaves your machine
- Ships as a Claude Code plugin: MCP server + skill that teaches the agent how to use it + guard hook

| Platform | Where local values are stored |
|---|---|
| macOS | Keychain |
| Windows | Credential Manager (max. 2560 bytes per value) |
| Linux | Secret Service (gnome-keyring, KWallet, KeePassXC) |

## Install

**As a Claude Code plugin** (MCP server, skill and guard hook in one step):

```
/plugin install tresor --marketplace Benewe1337/tresor
```

On first start the plugin installs its runtime dependencies (needs Node.js ≥ 20 and npm).

**Command-line tool** for storing tokens and unlocking password managers in your own terminal:

```bash
npm install -g github:Benewe1337/tresor
tresor --help
```

<details>
<summary>Manual setup without the plugin</summary>

```bash
git clone https://github.com/Benewe1337/tresor && cd tresor
npm install && npm run build && npm test && npm link
claude mcp add --scope user tresor -- tresor-mcp
```

Add the guard hook to `~/.claude/settings.json` under `hooks.PreToolUse`:

```json
{ "matcher": "Bash|PowerShell|Read|Grep|Edit|Write|NotebookEdit",
  "hooks": [{ "type": "command", "command": "tresor-guard", "timeout": 10 }] }
```

The skill lives in `skills/tresor/SKILL.md`; copy it to `~/.claude/skills/tresor/` if you want it without the plugin.
</details>

## Store a token locally

```bash
tresor set openai                       # paste the value, input is hidden
tresor set github --clip                # take it from the clipboard, then clear the clipboard
tresor set openai -d "Project X" --host api.openai.com   # only ever send it to this host
tresor list
tresor rm openai
```

Or let Claude ask: `tresor_request` opens a native dialog (macOS/Windows; zenity or kdialog on Linux, otherwise a one-time form on 127.0.0.1 in your browser). You paste the token there and it goes straight into the keychain. Never paste tokens into the chat.

## Link a password-manager entry

`tresor link` stores no value, only *where* it lives. tresor fetches it fresh through the manager's CLI every time it is used.

```bash
tresor providers                        # what is installed/unlocked, reference syntax
tresor link openai 1password "op://Private/OpenAI/credential"
tresor link github bitwarden "GitHub PAT#token"
tresor link stripe keepassxc "Dev/Stripe"
tresor link db pass "work/postgres#user"
```

| Provider | CLI | Reference | Setup |
|---|---|---|---|
| `1password` | `op` | `op://vault/item/field` | 1Password app → Developer → CLI integration (Touch ID / Windows Hello), or `OP_SERVICE_ACCOUNT_TOKEN` |
| `bitwarden` | `bw` | `item id or exact name[#password\|username\|notes\|totp\|uri\|field]` | `bw login`, then `tresor unlock bitwarden` (session kept in the keychain until `tresor lock bitwarden`). Vaultwarden works the same way. |
| `bws` | `bws` | secret UUID | `tresor setup bws` (access token) |
| `keepassxc` | `keepassxc-cli` | `group/entry[#attribute\|#totp]` | `tresor setup keepassxc --db file.kdbx [--keyfile k] [--no-password]` |
| `pass` | `pass` | `path[#field]` | gpg-agent |
| `gopass` | `gopass` | `path[#key]` | gpg-agent / age |
| `lastpass` | `lpass` | `name or id[#field]` | `lpass login` |

Claude can link entries too (`tresor_link`), but only after you approve it in a dialog.

**Custom providers** (Doppler, Infisical, HashiCorp Vault, Dashlane, …) go into `providers.json` in the tresor folder (`~/.config/tresor`, on Windows `%APPDATA%\tresor`):

```json
{
  "custom": {
    "doppler":   { "command": ["doppler", "secrets", "get", "{ref}", "--plain"] },
    "vault":     { "command": ["vault", "kv", "get", "-field=value", "{ref}"] },
    "infisical": { "command": ["infisical", "secrets", "get", "{ref}", "--output", "json"], "jsonPath": "0.secretValue" }
  }
}
```

`{ref}` is passed as a single argument, never through a shell. `jsonPath` (optional, dot-separated) picks the value out of JSON output.

## What Claude can do (MCP tools)

| Tool | Purpose |
|---|---|
| `tresor_list` | Names, descriptions, allowed hosts, source. Never values. |
| `tresor_providers` | Installed/unlocked password managers and their reference syntax |
| `tresor_request` | Open a dialog so you can enter a value |
| `tresor_link` | Link a password-manager entry, **only after you confirm in a dialog** |
| `tresor_run` | Run a command with `env: {"GH_TOKEN": "github"}`, output is redacted |
| `tresor_http` | HTTPS request with `{"Authorization": "Bearer {{secret:openai}}"}` |
| `tresor_write_file` | Write e.g. a `.env` with `KEY={{secret:openai}}` (mode 600); Claude cannot read it back |

Deliberately **missing**: any tool that returns a value, and any tool that deletes one.

The bundled skill (`skills/tresor/SKILL.md`) tells the agent when to reach for these tools, how to name secrets, and what to do with each error message.

## Starting other MCP servers with tokens

Instead of putting tokens into `~/.claude.json`:

```json
"my-mcp": { "command": "tresor", "args": ["run", "-e", "API_KEY=mymcp", "--", "npx", "-y", "my-mcp"] }
```

## Threat model

tresor protects against **accidental** leaks: tokens in the chat, in logs, in config files, in tool output (`env`, verbose curl, error messages). It redacts the value plus its Base64, URL-encoded and JSON-escaped forms.

It does **not** protect against an agent that is determined to get a value: anything allowed to run arbitrary commands with an injected token can transform it (reverse it, split it) or send it to a server of its choosing. What helps here: host pinning (`--host`, enforced by `tresor_http`), password-manager links requiring your approval, and reviewing `tresor_run` calls in the permission prompt.

The guard hook (`tresor-guard`) blocks, inside Claude sessions:
- reading OS credential stores directly (`security find-generic-password`, `secret-tool lookup`, `keyctl print`, `Get-StoredCredential`, `PasswordVault`, keyring libraries),
- read commands of password-manager CLIs (`op read`, `bw get`/`unlock`/`list`, `bws secret`, `keepassxc-cli show`, `pass show`, `gopass show`, `lpass show`),
- `tresor set|rm|run|link|unlock|setup`,
- reading files written by `tresor_write_file`.

Status commands like `bw status`, `op whoami` or `pass ls` stay allowed. If the hook input is malformed, it blocks (fails closed). It matches command text, so it can occasionally block a harmless command that merely *mentions* one of these patterns.

## Configuration

| Variable | Effect |
|---|---|
| `TRESOR_HOME` | Metadata folder (default `~/.config/tresor`, `%APPDATA%\tresor` on Windows) |
| `TRESOR_PROMPT=browser` | Always use the browser form instead of a native dialog (e.g. WSL) |
| `TRESOR_LINUX_STORE=keyutils` | Linux without Secret Service: kernel keyring, **lost on reboot** |

## How it works

- Local values: `@napi-rs/keyring`, service `tresor`, account = secret name. Provider sessions and passwords (Bitwarden session, KeePassXC password, bws token) are stored there as `__internal.*`.
- Metadata files contain no values: `index.json`, `providers.json`, `written-files.txt`.
- Processes are started without a shell via `cross-spawn` (including `.cmd` shims on Windows). The KeePassXC password is piped through stdin, never passed as an argument.

## Development

```bash
npm install && npm run build && npm test
TRESOR_INTEGRATION=1 npm test          # also hit the real OS credential store, pass and KeePassXC if installed
docker run --rm -v "$PWD":/src:ro node:22-bookworm bash /src/scripts/linux-integration.sh
```

`dist/` is committed so the plugin runs without a build step; CI fails if it is out of date. CI runs on macOS, Linux and Windows.

## License

[PolyForm Noncommercial 1.0.0](LICENSE): free for personal use, hobby projects, research, education and non-profit organisations.

**Commercial use** (at work, for clients, inside a company) needs a separate license. Open an issue or contact [@Benewe1337](https://github.com/Benewe1337) on GitHub.

Versions up to and including 0.2.0 (commit `c282ed5`) were published under the MIT License; copies of those versions keep that license.
