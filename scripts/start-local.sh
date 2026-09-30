#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
DIRECTORY=${1:-./var/local}
if [ ! -f "$DIRECTORY/config.json" ]; then
  node src/cli.mjs init --dir "$DIRECTORY"
fi
exec node src/cli.mjs serve --dir "$DIRECTORY" --port "${PORT:-8080}"
