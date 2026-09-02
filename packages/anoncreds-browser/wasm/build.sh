#!/usr/bin/env bash
# Rebuilds the anoncreds-rs WASM module. Requires the rust toolchain with the
# wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown).
set -euo pipefail
cd "$(dirname "$0")"

npx -y wasm-pack build --target web --out-dir pkg --release
# pkg output is committed, wasm-pack generates a .gitignore that would hide it
rm -f pkg/.gitignore
