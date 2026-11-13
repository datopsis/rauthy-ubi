#!/usr/bin/env bash
set -Eeuo pipefail
cd /src
# No resolver or network is available in this build stage.
npm --prefix frontend ci --offline --ignore-scripts --no-audit --no-fund
for feature in spow md; do
    cargo build --frozen --release -p rauthy-wasm-modules --target wasm32-unknown-unknown --features "${feature}"
    mkdir -p "frontend/src/wasm/${feature}"
    wasm-bindgen target/wasm32-unknown-unknown/release/wasm.wasm \
        --target bundler --out-dir "frontend/src/wasm/${feature}" --out-name "${feature}"
done
mkdir -p templates/html static/v1
npm --prefix frontend run build
cargo build --frozen --release --bin rauthy
sha256sum --check /upstream-locks.sha256
