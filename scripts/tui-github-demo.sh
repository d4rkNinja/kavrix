#!/usr/bin/env bash
set -euo pipefail
ROOT=/workspace/kavrix-tui-dev
DEMO_HOME=${KAVRIX_DEMO_HOME:-/workspace/kavrix-tui-demo-home}
export PATH="/home/box/.local/node/current/bin:$PATH"
export HOME="$DEMO_HOME"
export USERPROFILE="$DEMO_HOME"
export TERM=xterm-256color
export COLORTERM=truecolor
export FORCE_COLOR=1
unset NO_COLOR
cd "$ROOT"
echo "Using node: $(command -v node) $(node -v)" >&2
exec node "$ROOT/apps/cli/dist/bin.js" tui --color --config-dir "$DEMO_HOME/cfg"
