#!/usr/bin/env bash
# PreToolUse guard for tresor: keeps Claude from reading secret values around the MCP.
# Blocks (Bash): Keychain reads, keyring scripting, the tresor CLI except list/help.
# Blocks (Read/Grep/Bash): files that tresor_write_file filled with secrets.
# Defense in depth against accidents, not a sandbox — see README "Bedrohungsmodell".

input=$(cat)
tool=$(printf '%s' "$input" | jq -r '.tool_name // ""')
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // ""')
path=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_input.path // ""')
cwd=$(printf '%s' "$input" | jq -r '.cwd // ""')
registry="${TRESOR_HOME:-$HOME/.config/tresor}/written-files.txt"

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

if [ "$tool" = "Bash" ]; then
  if printf '%s' "$cmd" | grep -Eq '(find|dump)-(generic|internet)-password|dump-keychain|security[[:space:]]+-i|export-keychain'; then
    deny "tresor-guard: Schlüsselbund-Werte nicht auslesen. Nutze die tresor_* MCP-Tools (tresor_run, tresor_http)."
  fi
  if printf '%s' "$cmd" | grep -Eq '@napi-rs/keyring|keytar|from[[:space:]]+keyring|import[[:space:]]+keyring'; then
    deny "tresor-guard: Kein direkter Keyring-Zugriff. Nutze die tresor_* MCP-Tools."
  fi
  if printf '%s' "$cmd" | grep -Eq '(^|[;&|({[:space:]/])tresor[[:space:]]+(set|rm|delete|run)([[:space:]]|$)'; then
    deny "tresor-guard: tresor set/rm/run sind nur für Menschen im eigenen Terminal. Für Claude: tresor_request bzw. tresor_run."
  fi
fi

if [ -f "$registry" ]; then
  target="$path"
  [ "$tool" = "Bash" ] && target="$cmd"
  if [ -n "$target" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      rel="${f#"$cwd"/}"
      case "$target" in
        *"$f"*|*"$rel"*) deny "tresor-guard: $f enthält injizierte Secrets und ist für Claude gesperrt." ;;
      esac
    done < "$registry"
  fi
fi
exit 0
