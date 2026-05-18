#!/usr/bin/env bash
# ============================================================
# scripts/run-charlie.sh
# Attester-only node (not a block author).
# Charlie syncs the chain and runs an OCW that signs attestations
# whenever Charlie is in the on-chain fastlane authority set.
#
# Prereq: ./scripts/setup-keys.sh ./data/charlie local //Charlie
# ============================================================
set -euo pipefail

BASE_PATH="${BASE_PATH:-./data/charlie}"
NODE_BIN="${NODE_BIN:-./target/release/solochain-template-node}"
ALICE_PEER_ID="${ALICE_PEER_ID:-12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp}"

if [[ ! -d "${BASE_PATH}/chains" ]]; then
  echo "no keystore at ${BASE_PATH} — run:" >&2
  echo "  ./scripts/setup-keys.sh ${BASE_PATH} local //Charlie" >&2
  exit 1
fi

# No --validator flag (Charlie isn't an AURA block author).
# But --offchain-worker always so the FastLane OCW still runs and
# signs attestations.
exec "${NODE_BIN}" \
  --base-path "${BASE_PATH}" \
  --chain local \
  --name charlie \
  --port 30335 \
  --rpc-port 9946 \
  --rpc-cors all \
  --rpc-methods safe \
  --offchain-worker always \
  --enable-offchain-indexing true \
  --bootnodes "/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"
