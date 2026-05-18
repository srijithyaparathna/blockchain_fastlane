#!/usr/bin/env bash
# ============================================================
# scripts/run-dev.sh
# Start a single-node dev chain with a persistent keystore.
# RPC methods are kept SAFE — keys must already be on disk
# (run scripts/setup-keys.sh first).
# ============================================================
set -euo pipefail

BASE_PATH="${BASE_PATH:-./data/dev}"
NODE_BIN="${NODE_BIN:-./target/release/solochain-template-node}"

if [[ ! -d "${BASE_PATH}/chains" ]]; then
  echo "no keystore at ${BASE_PATH} — run:" >&2
  echo "  ./scripts/setup-keys.sh ${BASE_PATH} dev //Alice" >&2
  exit 1
fi

exec "${NODE_BIN}" \
  --base-path "${BASE_PATH}" \
  --chain dev \
  --validator \
  --rpc-port 9944 \
  --rpc-cors all \
  --rpc-methods safe \
  --offchain-worker always \
  --enable-offchain-indexing true
