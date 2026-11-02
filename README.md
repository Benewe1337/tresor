# tresor

Lokale API-Tokens im macOS-Schlüsselbund. Claude kann sie benutzen (als Env-Variable, im HTTP-Header, in einer `.env`), sieht aber nie den Wert. Kein Server, kein Master-Passwort, kein Bitwarden.

## Tokens speichern (du, im Terminal)

```bash
tresor set openai                       # Wert verdeckt einfügen
tresor set github --clip                # aus der Zwischenablage, danach wird sie geleert
tresor set openai -d "Projekt X" --host api.openai.com   # nur an diesen Host senden
tresor list
tresor rm openai
```

Oder Claude ruft `tresor_request` auf: Dann geht ein macOS-Dialog auf, du fügst den Token ein, er landet direkt im Schlüsselbund. Tokens nie in den Chat kopieren.

## Was Claude damit machen kann (MCP `tresor`)

| Tool | Zweck |
|---|---|
| `tresor_list` | Namen, Beschreibung, erlaubte Hosts. Keine Werte. |
| `tresor_request` | Dialog öffnen, du gibst den Wert ein |
| `tresor_run` | Befehl mit `env: {"GH_TOKEN":"github"}`, Ausgabe wird redigiert |
| `tresor_http` | HTTPS-Request, `{"Authorization":"Bearer {{secret:openai}}"}` |
| `tresor_write_file` | z.B. `.env` mit `KEY={{secret:openai}}`, mode 600, danach für Claude gesperrt |

Bewusst **nicht** vorhanden: ein Tool, das einen Wert zurückgibt, und ein Lösch-Tool.

## Andere MCP-Server mit Tokens starten

Statt Tokens in `~/.claude.json` zu schreiben:

```json
"mein-mcp": { "command": "tresor", "args": ["run", "-e", "API_KEY=meinmcp", "--", "npx", "-y", "mein-mcp"] }
```

## Bedrohungsmodell (ehrlich)

Schützt gegen **versehentliche** Leaks: Tokens im Chat, in Logs, in Configs, in Tool-Ausgaben (`env`, verbose curl, Fehlermeldungen). Redigiert werden der Wert sowie Base64-, URL- und JSON-Varianten.

Schützt **nicht** gegen einen Agenten, der es gezielt darauf anlegt: Wer beliebige Befehle mit injiziertem Token ausführen darf, kann ihn umformen (rückwärts, in Stücken) oder an einen eigenen Server schicken. Dagegen helfen nur `--host`-Pinning (gilt für `tresor_http`) und dass du die `tresor_run`-Aufrufe im Permission-Prompt ansiehst.

Der Guard-Hook (`hooks/tresor-guard.sh`, in `~/.claude/settings.json` eingetragen) blockt in Claude-Sessions: `security find-generic-password`/`dump-keychain`, direkten Keyring-Zugriff aus Skripten, `tresor set|rm|run` und das Lesen von Dateien, die `tresor_write_file` geschrieben hat.

## Technik

- Werte: macOS-Schlüsselbund, Dienst `tresor`, Konto = Name (`@napi-rs/keyring`). Nach einem Node-Update fragt macOS einmal nach Zugriff, dann „Immer erlauben“.
- Metadaten: `~/.config/tresor/index.json` (keine Werte), geschriebene Dateien: `~/.config/tresor/written-files.txt`.
- Build/Test: `npm install && npm run build && npm test` (Unit-, Hook- und Startup-Tests, inkl. echter stdio-Verbindung zum gebauten Server). Installation: `npm link`, `claude mcp add --scope user tresor -- tresor-mcp`.

## Installation

```bash
git clone https://github.com/Benewe1337/tresor && cd tresor
npm install && npm run build && npm test && npm link
claude mcp add --scope user tresor -- tresor-mcp
```

Guard-Hook in `~/.claude/settings.json` unter `hooks.PreToolUse` ergänzen (benötigt `jq`):

```json
{ "matcher": "Bash|Read|Grep|Edit|Write",
  "hooks": [{ "type": "command", "command": "/pfad/zu/tresor/hooks/tresor-guard.sh", "timeout": 10 }] }
```

Nur macOS (Schlüsselbund + Dialog). Lizenz: MIT.
