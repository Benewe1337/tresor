# tresor

API-Tokens für Claude Code, ohne dass Claude sie je sieht. Tokens liegen entweder lokal im Schlüsselbund des Systems oder bleiben in deinem Passwort-Manager. Claude kann sie benutzen (als Env-Variable, im HTTP-Header, in einer `.env`), bekommt aber nie den Wert.

Läuft auf **macOS, Windows und Linux**. Kein Server, kein eigenes Master-Passwort.

| | Wo der Wert liegt |
|---|---|
| macOS | Schlüsselbund |
| Windows | Anmeldeinformationsverwaltung (Credential Manager, max. 2560 Byte pro Wert) |
| Linux | Secret Service (gnome-keyring, KWallet, KeePassXC) |
| 1Password, Bitwarden, Bitwarden Secrets Manager, KeePassXC, pass, gopass, LastPass, eigene | bleibt im Passwort-Manager, tresor merkt sich nur die Referenz |

## Lokal speichern

```bash
tresor set openai                       # Wert verdeckt einfügen
tresor set github --clip                # aus der Zwischenablage, danach wird sie geleert
tresor set openai -d "Projekt X" --host api.openai.com   # nur an diesen Host senden
tresor list
tresor rm openai
```

Oder Claude ruft `tresor_request` auf: Dann geht ein Dialog auf (macOS/Windows nativ, Linux zenity/kdialog, sonst ein einmaliges Formular im Browser auf 127.0.0.1), du fügst den Token ein, er landet direkt im Schlüsselbund. Tokens nie in den Chat kopieren.

## Aus dem Passwort-Manager verknüpfen

`tresor link` speichert keinen Wert, nur *wo* er steht. Bei jeder Nutzung holt tresor ihn frisch über die CLI des Managers.

```bash
tresor providers                        # was ist installiert/entsperrt, Referenz-Syntax
tresor link openai 1password "op://Private/OpenAI/credential"
tresor link github bitwarden "GitHub PAT#token"
tresor link stripe keepassxc "Dev/Stripe"
tresor link db pass "work/postgres#user"
```

| Provider | CLI | Referenz | Einrichtung |
|---|---|---|---|
| `1password` | `op` | `op://Tresor/Eintrag/Feld` | 1Password-App → Entwickler → CLI-Integration (Touch ID / Windows Hello), oder `OP_SERVICE_ACCOUNT_TOKEN` |
| `bitwarden` | `bw` | `Eintrag-ID oder exakter Name[#password\|username\|notes\|totp\|uri\|Feld]` | `bw login`, dann `tresor unlock bitwarden` (Session liegt im Schlüsselbund bis `tresor lock bitwarden`). Vaultwarden geht genauso. |
| `bws` | `bws` | Secret-UUID | `tresor setup bws` (Access-Token) |
| `keepassxc` | `keepassxc-cli` | `Gruppe/Eintrag[#Attribut\|#totp]` | `tresor setup keepassxc --db pfad.kdbx [--keyfile k] [--no-password]` |
| `pass` | `pass` | `pfad[#feld]` | gpg-agent |
| `gopass` | `gopass` | `pfad[#key]` | gpg-agent / age |
| `lastpass` | `lpass` | `Name oder ID[#feld]` | `lpass login` |

**Eigene Provider** (Doppler, Infisical, HashiCorp Vault, Dashlane, …) in `providers.json` im tresor-Ordner (`~/.config/tresor`, Windows `%APPDATA%\tresor`):

```json
{
  "custom": {
    "doppler":   { "command": ["doppler", "secrets", "get", "{ref}", "--plain"] },
    "vault":     { "command": ["vault", "kv", "get", "-field=value", "{ref}"] },
    "infisical": { "command": ["infisical", "secrets", "get", "{ref}", "--output", "json"], "jsonPath": "0.secretValue" }
  }
}
```

`{ref}` wird als einzelnes Argument eingesetzt, ohne Shell. `jsonPath` (optional, Punkt-getrennt) holt den Wert aus JSON-Ausgabe.

## Was Claude damit machen kann (MCP `tresor`)

| Tool | Zweck |
|---|---|
| `tresor_list` | Namen, Beschreibung, erlaubte Hosts, Quelle. Keine Werte. |
| `tresor_providers` | Installierte/entsperrte Passwort-Manager und Referenz-Syntax |
| `tresor_request` | Dialog öffnen, du gibst den Wert ein |
| `tresor_link` | Passwort-Manager-Eintrag verknüpfen – **nur nach deiner Bestätigung im Dialog** |
| `tresor_run` | Befehl mit `env: {"GH_TOKEN":"github"}`, Ausgabe wird redigiert |
| `tresor_http` | HTTPS-Request, `{"Authorization":"Bearer {{secret:openai}}"}` |
| `tresor_write_file` | z.B. `.env` mit `KEY={{secret:openai}}`, mode 600, danach für Claude gesperrt |

Bewusst **nicht** vorhanden: ein Tool, das einen Wert zurückgibt, und ein Lösch-Tool.

## Andere MCP-Server mit Tokens starten

Statt Tokens in `~/.claude.json` zu schreiben:

```json
"mein-mcp": { "command": "tresor", "args": ["run", "-e", "API_KEY=meinmcp", "--", "npx", "-y", "mein-mcp"] }
```

## Installation

```bash
git clone https://github.com/Benewe1337/tresor && cd tresor
npm install && npm run build && npm test && npm link
claude mcp add --scope user tresor -- tresor-mcp
```

Guard-Hook in `~/.claude/settings.json` unter `hooks.PreToolUse` ergänzen (alle Plattformen, kein `jq` nötig):

```json
{ "matcher": "Bash|PowerShell|Read|Grep|Edit|Write|NotebookEdit",
  "hooks": [{ "type": "command", "command": "tresor-guard", "timeout": 10 }] }
```

Node ≥ 20. Linux braucht einen laufenden, entsperrten Secret Service. Ohne Desktop: `TRESOR_LINUX_STORE=keyutils` (Kernel-Keyring, geht beim Neustart verloren) bzw. `TRESOR_PROMPT=browser` für Dialoge.

## Bedrohungsmodell (ehrlich)

Schützt gegen **versehentliche** Leaks: Tokens im Chat, in Logs, in Configs, in Tool-Ausgaben (`env`, verbose curl, Fehlermeldungen). Redigiert werden der Wert sowie Base64-, URL- und JSON-Varianten.

Schützt **nicht** gegen einen Agenten, der es gezielt darauf anlegt: Wer beliebige Befehle mit injiziertem Token ausführen darf, kann ihn umformen (rückwärts, in Stücken) oder an einen eigenen Server schicken. Dagegen helfen `--host`-Pinning (gilt für `tresor_http`), dass Verknüpfungen mit dem Passwort-Manager nur nach deiner Bestätigung entstehen, und dass du `tresor_run`-Aufrufe im Permission-Prompt ansiehst.

Der Guard-Hook (`tresor-guard`) blockt in Claude-Sessions:
- direktes Auslesen der Schlüsselbünde (`security find-generic-password`, `secret-tool lookup`, `keyctl print`, `Get-StoredCredential`, `PasswordVault`, Keyring-Bibliotheken),
- Lese-Befehle der Passwort-Manager-CLIs (`op read`, `bw get`/`unlock`/`list`, `bws secret`, `keepassxc-cli show`, `pass show`, `gopass show`, `lpass show`),
- `tresor set|rm|run|link|unlock|setup`,
- das Lesen von Dateien, die `tresor_write_file` geschrieben hat.

Status-Befehle wie `bw status`, `op whoami`, `pass ls` bleiben erlaubt. Ist die Hook-Eingabe kaputt, blockt er (fail closed).

## Technik

- Werte lokal: `@napi-rs/keyring`, Dienst `tresor`, Konto = Name. Provider-Sitzungen/Passwörter (Bitwarden-Session, KeePassXC-Passwort, bws-Token) liegen dort unter `__internal.*`.
- Metadaten: `index.json` (keine Werte), `providers.json` (DB-Pfad, eigene Provider), `written-files.txt`.
- Prozesse ohne Shell über `cross-spawn` (auch `.cmd`-Shims unter Windows). KeePassXC-Passwort geht per stdin, nie per argv.
- Tests: `npm test` (Unit, MCP, Guard, Dialog-Fallback, Provider gegen Stub-CLIs). Integration gegen echte Systeme: `TRESOR_INTEGRATION=1 npm test`; Linux komplett per Docker: `docker run --rm -v "$PWD":/src:ro node:22-bookworm bash /src/scripts/linux-integration.sh`. CI läuft auf macOS, Linux und Windows.

Lizenz: MIT.
