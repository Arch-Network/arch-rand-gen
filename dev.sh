#!/usr/bin/env bash
# dev.sh — arch-rand-gen oracle development stack in a tmux session
#
# Windows:
#   oracle  — oracle server (listener + processor)
#   e2e     — end-to-end VRF fulfillment test
#
# Setup steps (build, key checks) run in the current terminal first,
# then a tmux session is created and attached.
#
# Assumptions:
#   • Arch localnet is ALREADY running on localhost:9002 / ws://localhost:10080
#   • ~/.arch/ keys exist: oracle.key, oracle_program.key, treasury.key, .oracle_ed.key
#     (run `make keygen` to generate .oracle_ed.key if missing)
#   • cargo-build-sbf is installed
#   • tmux is installed
#
# Usage:
#   ./dev.sh [options]
#
#   Options:
#     --skip-build   Skip cargo build / cargo build-sbf steps
#     --skip-e2e     Leave the e2e window as a plain shell (server only)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SKIP_BUILD=0
SKIP_E2E=0
SESSION="arch-rand-gen"
ROOT="$(cd "$(dirname "$0")" && pwd)"

# ── Arg parse ─────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    --skip-e2e)   SKIP_E2E=1 ;;
    *)            echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
log()  { echo -e "${CYN}[dev]${RST} $*"; }
ok()   { echo -e "${GRN}[ok]${RST}  $*"; }
warn() { echo -e "${YLW}[warn]${RST} $*"; }
die()  { echo -e "${RED}[err]${RST}  $*"; exit 1; }

# ── 0. Sanity checks ──────────────────────────────────────────────────────────
log "Checking prerequisites…"
command -v cargo           >/dev/null || die "cargo not found"
command -v cargo-build-sbf >/dev/null || die "cargo-build-sbf not found (install solana toolchain)"
command -v tmux            >/dev/null || die "tmux not found"

ARCH_DIR="${HOME}/.arch"
for key in oracle.key oracle_program.key treasury.key .oracle_ed.key; do
  [[ -f "${ARCH_DIR}/${key}" ]] || die "Missing key: ${ARCH_DIR}/${key} — see README for setup"
done
ok "All ~/.arch/ keys present"

if ! curl -sf http://localhost:9002 >/dev/null 2>&1; then
  warn "Arch RPC (localhost:9002) not responding — oracle server will retry on start"
fi

# ── 1. Build ──────────────────────────────────────────────────────────────────
if [[ $SKIP_BUILD -eq 0 ]]; then
  log "${BLD}Building oracle server…${RST}"
  cargo build -p server
  ok "Server built"

  log "${BLD}Building oracle on-chain program (SBF)…${RST}"
  (cd "$ROOT/oracle-program" && cargo build-sbf)
  ok "SBF program built → target/sbpf-solana-solana/release/oracle_program.so"
else
  log "Skipping build (--skip-build)"
fi

# ── 2. tmux session ───────────────────────────────────────────────────────────
log "${BLD}Launching tmux session '${SESSION}'…${RST}"

# Kill any stale session.
tmux kill-session -t "$SESSION" 2>/dev/null || true

CMD_SERVER="cd '$ROOT' && cargo run -p server"

# e2e: wait for the oracle server WebSocket to be reachable, then run the test.
E2E_WAIT="until curl -s http://localhost:9002 >/dev/null 2>&1; do sleep 1; done"
CMD_E2E="cd '$ROOT' && echo 'Waiting for localnet…' && $E2E_WAIT && echo 'Running e2e…' && \
  cargo test -p e2e-tests -- test_deploy_and_request_randomness --include-ignored --nocapture"

# Window 0: oracle server
tmux new-session  -d -s "$SESSION" -n "oracle" -x "$(tput cols)" -y "$(tput lines)"
tmux send-keys    -t "$SESSION:oracle" "$CMD_SERVER" Enter

# Window 1: e2e tests
tmux new-window   -t "$SESSION" -n "e2e"
if [[ $SKIP_E2E -eq 0 ]]; then
  tmux send-keys  -t "$SESSION:e2e" "$CMD_E2E" Enter
fi

# Focus the oracle window on attach.
tmux select-window -t "$SESSION:oracle"

ok "Attaching — Ctrl+B N/P to switch windows, Ctrl+B D to detach, Ctrl+B & to kill window"
tmux attach-session -t "$SESSION"
