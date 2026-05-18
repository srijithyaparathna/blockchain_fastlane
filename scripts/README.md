# FastLane deployment scripts

These scripts replace the dev-only `--rpc-methods unsafe` + `author_insertKey`
curl flow with a production-style setup: keys live on disk in a persistent
keystore directory, populated **before** the node ever starts.

## Build once

```bash
cargo build --release
```

## Single-node dev chain

```bash
# 1. Populate keystore for Alice (the only authority in dev preset).
./scripts/setup-keys.sh ./data/dev dev //Alice

# 2. Start the node. RPC stays in --rpc-methods=safe; OCW finds keys natively.
./scripts/run-dev.sh
```

In Polkadot.js Apps (`ws://127.0.0.1:9944`), submit a payload from any account.
You should see `Submitted → PreConsensed → Finalised` within ~2 blocks.

## Multi-validator local network (matches your stated target)

```bash
# Two terminals worth of work — one per validator. Each gets its OWN keystore
# directory, so neither node has the other's private keys.

# Validator 1
./scripts/setup-keys.sh ./data/alice local //Alice
./scripts/run-alice.sh

# Validator 2 (separate terminal)
./scripts/setup-keys.sh ./data/bob local //Bob
./scripts/run-bob.sh
```

Threshold is 2; both OCWs sign independently and both signatures must land
before `PreConsensed` is reached. This is the topology mainnet would use,
modulo running each on its own host.

## Real production checklist

Beyond what the scripts provide:

1. **Generate fresh keys per validator** — never deploy with `//Alice`. Use
   `./target/release/solochain-template-node key generate --scheme sr25519`,
   record the SURI (mnemonic) once into a sealed secret store, throw away
   the on-screen output. `setup-keys.sh` already accepts the SURI via stdin
   or `$FASTLANE_SURI` so it's not in shell history.
2. **Lock down RPC** — the scripts set `--rpc-methods safe`. Also bind to
   localhost (`--rpc-port` is already that by default; do not pass
   `--rpc-external` unless you front it with TLS + auth).
3. **Persist `--base-path` on encrypted storage** — the keystore files are
   not encrypted at rest, so the volume must be.
4. **Replace `--node-key` with a generated one** — the fixed key in
   `run-alice.sh` is for local-network reproducibility only.
5. **Replace `pallet-sudo` with real governance** before mainnet — sudo
   defeats the slashing mechanism if it's controlled by anyone other than
   on-chain governance.
