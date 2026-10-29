#!/bin/sh
# Recompila app/static/app.css. Ejecútalo cada vez que cambies clases en app/templates.
# Usa el CLI standalone de Tailwind v3 (no requiere Node).
set -e
cd "$(dirname "$0")/.."
CLI="${TAILWIND_CLI:-/tmp/tailwindcss}"
if [ ! -x "$CLI" ]; then
  curl -sL -o "$CLI" https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64
  chmod +x "$CLI"
fi
"$CLI" -c tailwind.config.js -i frontend/input.css -o app/static/app.css --minify
