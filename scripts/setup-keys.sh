#!/usr/bin/env bash
# ============================================================
# scripts/setup-keys.sh
# Populate a node's on-disk keystore with the keys the OCW needs
# BEFORE the node starts. No --rpc-methods unsafe, no curl.
#
# Production note: the SURI is read from stdin (or $FASTLANE_SURI)
# so it never lands in shell history. For real validator deployment
# generate a fresh key with `node key generate` and store the SURI
# in a hardware module / sealed secret — //Alice etc. are dev only.
#
# Usage:
#   ./scripts/setup-keys.sh <base-path> <chain> [<suri>]
#
#   ./scripts/setup-keys.sh ./data/alice dev //Alice
#   ./scripts/setup-keys.sh ./data/alice local //Alice
#   FASTLANE_SURI="//Alice" ./scripts/setup-keys.sh ./data/alice dev
# ============================================================
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <base-path> <chain> [<suri>]" >&2
  exit 64
fi

BASE_PATH="$1"
CHAIN="$2"
SURI="${3:-${FASTLANE_SURI:-}}"

if [[ -z "${SURI}" ]]; then
  read -rsp "SURI (e.g. //Alice or 12-word phrase): " SURI
  echo
fi

NODE_BIN="${NODE_BIN:-./target/release/solochain-template-node}"
if [[ ! -x "${NODE_BIN}" ]]; then
  echo "node binary not found at ${NODE_BIN}; run \`cargo build --release\` first" >&2
  exit 1
fi

mkdir -p "${BASE_PATH}"

# Insert under the "fast" KeyTypeId — this is what the FastLane OCW reads.
# The keystore file ends up at ${BASE_PATH}/chains/<chain-id>/keystore/.
"${NODE_BIN}" key insert \
  --base-path "${BASE_PATH}" \
  --chain "${CHAIN}" \
  --scheme sr25519 \
  --suri "${SURI}" \
  --key-type fast

# Also insert the AURA + GRANDPA session keys so the node can author
# blocks. Skip if you've already done this for this base-path.
"${NODE_BIN}" key insert \
  --base-path "${BASE_PATH}" \
  --chain "${CHAIN}" \
  --scheme sr25519 \
  --suri "${SURI}" \
  --key-type aura

"${NODE_BIN}" key insert \
  --base-path "${BASE_PATH}" \
  --chain "${CHAIN}" \
  --scheme ed25519 \
  --suri "${SURI}" \
  --key-type gran

# Generate the libp2p node identity key (separate from validator service keys).
# This determines the node's PeerId. Written once and persists forever.
"${NODE_BIN}" key generate-node-key \
  --base-path "${BASE_PATH}" \
  --chain "${CHAIN}" \
  2>/dev/null || true   # silently no-op if it already exists

echo
echo "keystore populated:"
find "${BASE_PATH}/chains" -maxdepth 5 \( -path '*/keystore/*' -o -name 'secret_ed25519' \) | sort
