#!/usr/bin/env bash
set -Eeuo pipefail
cd /src
if test "$(uname -m)" = aarch64; then
    export JEMALLOC_SYS_WITH_LG_PAGE=16
fi
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
# Upstream deliberately permits a missing dataset ONLY to bootstrap this debug tool.
# The release build below still requires the real generated dataset. No bypass or placeholder.
CARGO_PROFILE_DEV_DEBUG=0 cargo run --frozen --bin fido-mds-prep -- \
    --source /bundle/fido-mds.jwt --out assets/fido_mds/dataset.bin
test -s assets/fido_mds/dataset.bin
rm -rf target/debug
cargo build --frozen --release --bin rauthy
sha256sum --check /upstream-locks.sha256
