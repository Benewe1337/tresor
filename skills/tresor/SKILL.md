---
name: tresor
description: Use API tokens, passwords and other credentials without ever seeing them, via the tresor MCP tools (tresor_list, tresor_request, tresor_link, tresor_run, tresor_http, tresor_write_file). Use whenever a task needs a secret — calling an authenticated API, running a CLI that wants a token (gh, vercel, stripe, openai, aws …), creating a .env, configuring an MCP server with credentials, or when the user mentions a token, API key, password, 1Password, Bitwarden, KeePassXC or pass. Also use when the user is about to paste a token into the chat.
---

# tresor: use secrets without seeing them

tresor keeps the user's tokens in the OS keychain or in their password manager. You work with **names** (`openai`, `github`); tresor puts the real value into the process, request or file and redacts it from everything you get back (`[tresor:openai]`).

**Never** ask the user to paste a token into the chat. If they do it anyway, do not repeat or use it; tell them to rotate it and store the new one with `tresor_request`.

## 1. Find or create the secret

1. `tresor_list` shows names, descriptions, allowed hosts and where each value lives (`source` = linked password-manager entry, otherwise local).
2. Not there yet? Pick one:
   - **The user has it at hand:** `tresor_request` with a clear `name`, a `description` saying what it is and where to get it, and `hosts` when it is an API token (e.g. `["api.openai.com"]`). A dialog opens; you only learn saved/cancelled.
   - **It is in their password manager:** `tresor_providers` shows what is installed/unlocked and the reference syntax. Ask the user for the exact reference (do not guess item names), then `tresor_link`. The user approves in a dialog; the reply says whether a test fetch worked.

Name secrets after the service, lowercase with dashes: `openai`, `github-ci`, `stripe-test`.

## 2. Use it

| Situation | Tool | Example |
|---|---|---|
| CLI that reads a token from env | `tresor_run` | `{"command": ["gh", "api", "user"], "env": {"GH_TOKEN": "github"}}` |
| Needs a shell (pipes, `$VAR`) | `tresor_run` | `{"command": ["sh", "-c", "curl -s -H \"Authorization: Bearer $T\" https://api.example.com/me"], "env": {"T": "example"}}` (Windows: `["powershell", "-Command", "…"]`) |
| Plain HTTPS API call | `tresor_http` | `{"url": "https://api.openai.com/v1/models", "headers": {"Authorization": "Bearer {{secret:openai}}"}}` |
| Project needs a `.env` / config file | `tresor_write_file` | `{"path": "/abs/project/.env", "content": "OPENAI_API_KEY={{secret:openai}}\n"}` |
| MCP server or long-running process needs a token | edit its config to start through the CLI | `"command": "tresor", "args": ["run", "-e", "API_KEY=name", "--", "npx", "-y", "some-mcp"]` |

Rules of thumb:
- Prefer env vars over `{{secret:NAME}}` in command args (args are visible in the process list).
- `tresor_http` sends secrets only over HTTPS (or to localhost), never follows redirects, and refuses hosts a secret is not pinned to.
- Before `tresor_write_file`, make sure the target is gitignored (check `.gitignore`, add the entry if missing). You will not be able to read the file afterwards; that is intended.
- Output shows `[tresor:NAME]` where a value appeared. That means injection worked; do not try to "fix" it.

## 3. When something fails

| Message | What to do |
|---|---|
| `Unknown secret "x"` | Check `tresor_list`; create it (step 1). |
| `Bitwarden is locked` | Ask the user to run `tresor unlock bitwarden` in **their own terminal**, then retry. |
| `KeePassXC is not set up` / `password missing` | User runs `tresor setup keepassxc --db <file.kdbx>`. |
| `No access token … tresor setup bws` | User runs `tresor setup bws`. |
| 1Password `not signed in` | User enables the 1Password app's CLI integration or runs `op signin`. |
| `… is not installed or not on PATH` | That password-manager CLI is missing; tell the user which one. |
| `may only be sent to: …` | The secret is pinned to other hosts. Do not work around it; ask the user. |
| `Credential store: …` (Linux) | No unlocked Secret Service; the user needs gnome-keyring/KWallet/KeePassXC running. |
| Hook says `tresor-guard: …` | You tried to read a secret directly. Stop and use the tools above instead. |

The `tresor` terminal commands (`set`, `rm`, `run`, `link`, `unlock`, `setup`) are for the user in their own terminal. You cannot run them, and you should not try to work around the guard.

## Removing or changing secrets

You cannot delete secrets. To replace a value, call `tresor_request` with the same name (local secrets only). For deletion, tell the user to run `tresor rm <name>`.
