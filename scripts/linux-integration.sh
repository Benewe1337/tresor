#!/usr/bin/env bash
# Linux integration run: real Secret Service (gnome-keyring on a private D-Bus),
# real pass+gpg and keepassxc-cli. Used by CI and locally via Docker:
#   docker run --rm -v "$PWD":/src:ro node:22-bookworm bash /src/scripts/linux-integration.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! command -v gnome-keyring-daemon >/dev/null; then
  ${SUDO:-} apt-get update -qq
  ${SUDO:-} apt-get install -y -qq --no-install-recommends gnome-keyring dbus dbus-x11 pass gnupg keepassxc >/dev/null
fi
if [ -d /src ]; then
  mkdir -p /work && cp -a /src/. /work/ && rm -rf /work/node_modules /work/dist && cd /work
fi
npm ci --silent
npm run build --silent
dbus-run-session -- bash -c '
  printf "keyring-pass" | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  TRESOR_INTEGRATION=1 npx vitest run
'
