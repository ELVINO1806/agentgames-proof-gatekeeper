#!/bin/sh
# Download the official gatekeeper circuit artifacts into ./circuits/
# (they are public files served by the Agent Games site).
set -e
cd "$(dirname "$0")/.."
mkdir -p circuits
curl -sL https://agentgames.zkverify.io/circuits/gatekeeper.wasm -o circuits/gatekeeper.wasm
curl -sL https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey -o circuits/gatekeeper_final.zkey
ls -la circuits/
echo "Set GATEKEEPER_WASM=./circuits/gatekeeper.wasm and GATEKEEPER_ZKEY=./circuits/gatekeeper_final.zkey if you use this location."
