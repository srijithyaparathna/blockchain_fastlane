#!/usr/bin/env bash
# ============================================================
# scripts/run-alice.sh
# Validator #1 of a multi-validator local network.
# Prereq: ./scripts/setup-keys.sh ./data/alice local //Alice
# ============================================================
set -euo pipefail

BASE_PATH="${BASE_PATH:-./data/alice}"
NODE_BIN="${NODE_BIN:-./target/release/solochain-template-node}"

if [[ ! -d "${BASE_PATH}/chains" ]]; then
  echo "no keystore at ${BASE_PATH} — run:" >&2
  echo "  ./scripts/setup-keys.sh ${BASE_PATH} local //Alice" >&2
  exit 1
fi

exec "${NODE_BIN}" \
  --base-path "${BASE_PATH}" \
  --chain local \
  --name alice \
  --validator \
  --port 30333 \
  --rpc-port 9944 \
  --rpc-cors all \
  --rpc-methods safe \
  --offchain-worker always \
  --enable-offchain-indexing true \
  --node-key 0000000000000000000000000000000000000000000000000000000000000001
