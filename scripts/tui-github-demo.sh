#!/usr/bin/env bash
set -euo pipefail
export PATH="/home/box/.local/node/current/bin:$PATH"
export HOME=/workspace/kavrix-tui-demo-home
export USERPROFILE="$HOME"
export TERM=xterm-256color
export COLORTERM=truecolor
export FORCE_COLOR=1
export COLUMNS="${COLUMNS:-120}"
export LINES="${LINES:-36}"
unset NO_COLOR CI
cd /workspace/kavrix-tui-dev
# xfce4-terminal -e can leave stdout non-TTY; reattach so Ink mounts
exec </dev/tty >/dev/tty 2>/dev/tty
exec node /workspace/kavrix-tui-dev/apps/cli/dist/bin.js tui --color --config-dir /workspace/kavrix-tui-demo-home/cfg
